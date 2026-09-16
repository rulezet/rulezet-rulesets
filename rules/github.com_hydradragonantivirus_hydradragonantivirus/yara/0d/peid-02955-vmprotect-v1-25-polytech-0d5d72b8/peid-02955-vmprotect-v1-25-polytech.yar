rule PEiD_02955_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 E0 3C 8B 14 07 83 ED 04 89 55 00 E9 }

  condition:
    $a
}