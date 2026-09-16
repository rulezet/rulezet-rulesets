rule PEiD_02512_VMProtect_v1_25_____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 --> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 }

  condition:
    $a
}