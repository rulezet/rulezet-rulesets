rule PEiD_00201_ASPack_v1_00b_ {
  meta:
    description = "[ASPack v1.00b]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44 }

  condition:
    $a
}