rule PEiD_03524_yoda_s_Protector_1_02___exe__scr__com_____Ashkbiz_Danehkar__h__ {
  meta:
    description = "[yoda's Protector 1.02 (.exe,.scr,.com) -> Ashkbiz Danehkar (h)]"
    ep_only     = "false"

  strings:
    $a = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 }

  condition:
    $a
}