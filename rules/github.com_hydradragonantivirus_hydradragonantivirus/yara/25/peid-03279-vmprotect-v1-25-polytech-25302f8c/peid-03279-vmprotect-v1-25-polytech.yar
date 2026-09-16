rule PEiD_03279_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 }

  condition:
    $a
}