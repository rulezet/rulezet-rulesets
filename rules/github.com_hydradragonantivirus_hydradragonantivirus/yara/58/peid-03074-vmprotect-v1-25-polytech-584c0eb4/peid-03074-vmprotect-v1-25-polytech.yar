rule PEiD_03074_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5F 58 5A 5E 5D 5E 5B 59 C3 }

  condition:
    $a
}