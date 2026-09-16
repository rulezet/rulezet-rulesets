rule PEiD_03019_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 5D 59 5F 5E 58 58 5A 5B C3 }

  condition:
    $a
}