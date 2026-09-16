rule PEiD_03079_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 5E 5F 5D 5A 58 5B 9D 59 C3 }

  condition:
    $a
}