rule PEiD_03050_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5F 5E 5B 9D 58 5B 59 5A C3 }

  condition:
    $a
}