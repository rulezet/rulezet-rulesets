rule PEiD_02403_UPolyX_v0_5_ {
  meta:
    description = "[UPolyX v0.5]"
    ep_only     = "false"

  strings:
    $a = { 83 EC 04 89 ?? 24 59 ?? ?? 00 00 00 }

  condition:
    $a
}