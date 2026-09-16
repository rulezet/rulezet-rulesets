rule PEiD_03127_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5D 5A 58 9D 5B 5E 5F 58 C3 }

  condition:
    $a
}