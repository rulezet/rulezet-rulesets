rule PEiD_03031_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 58 5A 5F 5B 5E 5D 5D 9D C3 }

  condition:
    $a
}