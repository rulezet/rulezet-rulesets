rule PEiD_03012_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5A 5E 5E 59 9D 5D 5B 58 C3 }

  condition:
    $a
}