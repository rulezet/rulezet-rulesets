rule PEiD_02510_VMProtect_v1_25_____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 --> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 }

  condition:
    $a
}