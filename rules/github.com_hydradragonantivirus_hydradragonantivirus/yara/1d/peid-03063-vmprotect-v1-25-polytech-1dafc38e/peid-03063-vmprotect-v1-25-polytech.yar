rule PEiD_03063_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5D 58 59 9D 5E 5B 5A 5E C3 }

  condition:
    $a
}