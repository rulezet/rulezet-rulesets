rule PEiD_03529_yoda_s_Protector_1_0b____Ashkbiz_Danehkar_ {
  meta:
    description = "[yoda's Protector 1.0b -> Ashkbiz Danehkar]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 }

  condition:
    $a
}