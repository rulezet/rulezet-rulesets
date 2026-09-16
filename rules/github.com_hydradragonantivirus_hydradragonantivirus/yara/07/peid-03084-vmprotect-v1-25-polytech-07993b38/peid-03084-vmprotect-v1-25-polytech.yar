rule PEiD_03084_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5D 5F 5B 5E 9D 58 5A 5B C3 }

  condition:
    $a
}