rule PEiD_03112_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5E 5B 58 9D 59 5D 5F 5A C3 }

  condition:
    $a
}