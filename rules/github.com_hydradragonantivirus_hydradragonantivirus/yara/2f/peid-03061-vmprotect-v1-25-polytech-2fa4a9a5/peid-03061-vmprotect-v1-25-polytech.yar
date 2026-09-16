rule PEiD_03061_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 58 5B 9D 5A 5D 5F 5E 59 C3 }

  condition:
    $a
}