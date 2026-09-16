rule PEiD_03139_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5B 59 5E 5F 5D 5A 9D 58 58 C3 }

  condition:
    $a
}