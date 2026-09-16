rule PEiD_03122_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 58 5A 5B 5E 5F 9D 5D 5F 59 C3 }

  condition:
    $a
}