rule PEiD_02696_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 56 52 9C 50 53 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 59 5F 5D 5B 58 9D 5A 5E 59 59 C3 }

  condition:
    $a
}