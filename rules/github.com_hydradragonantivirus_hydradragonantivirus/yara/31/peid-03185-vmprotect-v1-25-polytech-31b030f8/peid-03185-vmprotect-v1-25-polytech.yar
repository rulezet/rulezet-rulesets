rule PEiD_03185_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 46 83 C5 02 88 14 07 E9 }

  condition:
    $a
}