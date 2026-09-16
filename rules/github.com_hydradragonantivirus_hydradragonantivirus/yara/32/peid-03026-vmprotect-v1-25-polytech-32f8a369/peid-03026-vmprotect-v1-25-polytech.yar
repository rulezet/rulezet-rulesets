rule PEiD_03026_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5B 9D 5A 5F 5D 5A 5E 59 C3 }

  condition:
    $a
}