rule PEiD_02632_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 56 9C 53 54 57 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3 }

  condition:
    $a
}