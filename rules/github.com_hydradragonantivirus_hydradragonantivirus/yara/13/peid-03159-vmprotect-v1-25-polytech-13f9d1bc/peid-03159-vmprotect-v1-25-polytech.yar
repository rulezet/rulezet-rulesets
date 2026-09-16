rule PEiD_03159_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5F 5F 5B 58 59 5D 5A 5E 9D C3 }

  condition:
    $a
}