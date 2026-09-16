rule PEiD_03149_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 58 5F 5D 5A 59 9D 5A 5B C3 }

  condition:
    $a
}