rule PEiD_03165_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 5F 59 5D 5A 5B 5B 5E 58 C3 }

  condition:
    $a
}