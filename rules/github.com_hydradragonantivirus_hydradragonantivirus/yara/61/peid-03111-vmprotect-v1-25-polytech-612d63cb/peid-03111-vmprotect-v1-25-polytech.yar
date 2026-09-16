rule PEiD_03111_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5E 5A 58 5D 9D 59 5F 5B C3 }

  condition:
    $a
}