rule PEiD_03269_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 EE FC E9 }

  condition:
    $a
}