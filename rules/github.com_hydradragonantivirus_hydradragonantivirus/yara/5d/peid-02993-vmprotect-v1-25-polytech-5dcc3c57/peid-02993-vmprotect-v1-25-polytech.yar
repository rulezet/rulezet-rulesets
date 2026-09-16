rule PEiD_02993_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5F 5A 59 58 5D 9D 5E 5A C3 }

  condition:
    $a
}