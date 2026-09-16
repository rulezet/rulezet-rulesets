rule PEiD_03317_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 55 50 52 56 51 50 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 59 5F 5B 5A 59 5E 5A 58 5D 9D C3 }

  condition:
    $a
}