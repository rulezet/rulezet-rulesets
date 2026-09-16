rule PEiD_00816_FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0)]"
    ep_only     = "true"

  strings:
    $a = { 91 EB 02 CD 20 BF 50 BC 04 6F 91 BE D0 ?? ?? 6F EB 02 CD 20 2B F7 EB 02 F0 46 8D 1D F4 00 }

  condition:
    $a
}