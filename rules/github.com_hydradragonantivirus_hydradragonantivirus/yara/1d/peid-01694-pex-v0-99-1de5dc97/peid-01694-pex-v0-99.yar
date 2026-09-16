rule PEiD_01694_PEX_v0_99_ {
  meta:
    description = "[PEX v0.99]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 01 ?? ?? ?? ?? 83 C4 04 E8 01 ?? ?? ?? ?? 5D 81 }

  condition:
    $a
}