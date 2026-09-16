rule PEiD_03292_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 00 83 C5 02 8A 02 66 89 45 00 E9 }

  condition:
    $a
}