rule PEiD_03280_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 4D 04 83 ED 02 D3 E0 89 45 04 9C 8F 45 00 E9 }

  condition:
    $a
}