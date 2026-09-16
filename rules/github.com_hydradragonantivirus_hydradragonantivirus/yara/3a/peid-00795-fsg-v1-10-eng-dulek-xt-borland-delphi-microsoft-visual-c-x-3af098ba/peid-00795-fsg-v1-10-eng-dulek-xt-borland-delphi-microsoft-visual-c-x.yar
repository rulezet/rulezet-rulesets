rule PEiD_00795_FSG_v1_10__Eng_____dulek_xt_____Borland_Delphi___Microsoft_Visual_C___x_ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Microsoft Visual C++)x]"
    ep_only     = "true"

  strings:
    $a = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 }

  condition:
    $a
}