rule PEiD_00823_FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0)]"
    ep_only     = "true"

  strings:
    $a = { EB 02 CD 20 ?? CF ?? ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $a
}