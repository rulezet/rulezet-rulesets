rule PEiD_03088_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 59 5F 58 5E 9D 5D 5F 5B C3 }

  condition:
    $a
}