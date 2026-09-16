rule PEiD_01551_PECompact_v0_978_1_ {
  meta:
    description = "[PECompact v0.978.1]"
    ep_only     = "true"

  strings:
    $a = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 49 87 40 ?? 87 DD 8B 85 CE 87 }

  condition:
    $a
}