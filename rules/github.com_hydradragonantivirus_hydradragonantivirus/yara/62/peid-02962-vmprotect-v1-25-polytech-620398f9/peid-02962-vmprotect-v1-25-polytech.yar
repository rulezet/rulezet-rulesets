rule PEiD_02962_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5B 5E 5D 58 5F 9D 59 5A C3 }

  condition:
    $a
}