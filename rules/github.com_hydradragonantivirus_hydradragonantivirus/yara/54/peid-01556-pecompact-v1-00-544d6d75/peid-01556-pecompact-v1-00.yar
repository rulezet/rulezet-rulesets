rule PEiD_01556_PECompact_v1_00_ {
  meta:
    description = "[PECompact v1.00]"
    ep_only     = "true"

  strings:
    $a = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB C4 84 40 ?? 87 DD 8B 85 49 85 }

  condition:
    $a
}