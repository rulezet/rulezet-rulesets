rule PEiD_02972_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5B 9D 5E 5F 5A 58 5D 5D C3 }

  condition:
    $a
}