rule PEiD_03262_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 45 00 83 ED 02 00 45 04 9C 8F 45 00 E9 }

  condition:
    $a
}