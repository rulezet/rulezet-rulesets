rule PEiD_03073_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5D 5A 5B 58 5F 5E 5E 59 C3 }

  condition:
    $a
}