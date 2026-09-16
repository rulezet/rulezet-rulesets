rule PEiD_03128_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5E 5A 5F 5B 9D 5B 58 5D C3 }

  condition:
    $a
}