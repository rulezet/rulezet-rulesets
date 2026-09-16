rule PEiD_02998_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 59 9D 5D 58 5B 5E 5A 5F C3 }

  condition:
    $a
}