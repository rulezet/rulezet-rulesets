rule PEiD_01518_PE_Armor_0_49____Hying_ {
  meta:
    description = "[PE-Armor 0.49 -> Hying]"
    ep_only     = "true"

  strings:
    $a = { 56 52 51 53 55 E8 15 01 00 00 32 ?? ?? 00 00 00 00 00 }

  condition:
    $a
}