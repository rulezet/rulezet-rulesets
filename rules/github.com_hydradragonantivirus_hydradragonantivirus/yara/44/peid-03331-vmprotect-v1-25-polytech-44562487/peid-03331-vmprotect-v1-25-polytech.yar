rule PEiD_03331_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 57 52 53 51 55 50 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 80 E0 3C 8B 14 07 83 ED 04 89 55 00 E9 }

  condition:
    $a
}