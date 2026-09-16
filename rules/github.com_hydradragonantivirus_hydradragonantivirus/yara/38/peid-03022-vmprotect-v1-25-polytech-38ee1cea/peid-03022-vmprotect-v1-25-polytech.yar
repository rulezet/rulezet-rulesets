rule PEiD_03022_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5A 9D 5D 59 5B 59 5E 5F C3 }

  condition:
    $a
}