rule PEiD_02634_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 57 9C 54 53 55 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }

  condition:
    $a
}