rule PEiD_02940_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 8D 76 02 98 83 ED 04 89 45 00 E9 }

  condition:
    $a
}