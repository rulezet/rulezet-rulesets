rule PEiD_00797_FSG_v1_10__Eng_____dulek_xt_____MASM32___TASM32___Microsoft_Visual_Basic__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (MASM32 / TASM32 / Microsoft Visual Basic)]"
    ep_only     = "true"

  strings:
    $a = { F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94 }

  condition:
    $a
}