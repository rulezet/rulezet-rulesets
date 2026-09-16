rule PEiD_03024_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5B 59 5F 5A 5E 5D 9D 5A C3 }

  condition:
    $a
}