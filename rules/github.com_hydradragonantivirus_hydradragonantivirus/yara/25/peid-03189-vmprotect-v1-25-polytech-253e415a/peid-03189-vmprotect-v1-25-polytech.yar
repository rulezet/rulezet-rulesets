rule PEiD_03189_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 66 89 14 07 83 C6 01 E9 }

  condition:
    $a
}