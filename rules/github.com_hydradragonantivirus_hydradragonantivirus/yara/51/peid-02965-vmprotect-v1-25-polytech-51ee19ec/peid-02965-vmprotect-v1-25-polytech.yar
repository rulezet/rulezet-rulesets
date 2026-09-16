rule PEiD_02965_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5F 5B 5F 5D 59 5E 9D 5A C3 }

  condition:
    $a
}