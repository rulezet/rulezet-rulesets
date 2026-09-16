rule PEiD_03130_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5F 5B 58 5A 9D 58 5E 5D C3 }

  condition:
    $a
}