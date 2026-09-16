rule PEiD_03011_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5A 5B 5E 5D 5B 9D 59 58 C3 }

  condition:
    $a
}