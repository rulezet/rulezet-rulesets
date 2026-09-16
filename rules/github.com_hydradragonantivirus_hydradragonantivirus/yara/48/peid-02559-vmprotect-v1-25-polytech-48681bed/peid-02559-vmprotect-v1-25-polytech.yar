rule PEiD_02559_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 83 EE FF 98 83 ED 04 89 45 00 E9 }

  condition:
    $a
}