rule PEiD_03295_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 47 50 39 C5 0F 87 ?? ?? ?? ?? 8D 4F 40 29 E1 8D 45 80 29 C8 89 C4 9C 56 89 FE 8D BD 40 FF FF FF 57 FC F3 A4 5F 5E 9D E9 }

  condition:
    $a
}