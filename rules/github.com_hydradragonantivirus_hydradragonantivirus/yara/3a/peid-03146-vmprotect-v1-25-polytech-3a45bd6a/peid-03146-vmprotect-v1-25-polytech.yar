rule PEiD_03146_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 9D 59 5F 5D 58 5E 5A 5B C3 }

  condition:
    $a
}