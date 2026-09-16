rule PEiD_01538_PEBundle_v2_44_ {
  meta:
    description = "[PEBundle v2.44]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 83 BD }

  condition:
    $a
}