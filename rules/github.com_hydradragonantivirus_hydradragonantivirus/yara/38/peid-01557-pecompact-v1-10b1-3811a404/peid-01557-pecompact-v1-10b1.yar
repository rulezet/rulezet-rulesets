rule PEiD_01557_PECompact_v1_10b1_ {
  meta:
    description = "[PECompact v1.10b1]"
    ep_only     = "true"

  strings:
    $a = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 28 63 40 ?? 87 DD 8B 85 AD 63 }

  condition:
    $a
}