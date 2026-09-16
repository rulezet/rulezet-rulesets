rule PEiD_02458_UPX_HiT_v0_0_1_ {
  meta:
    description = "[UPX$HiT v0.0.1]"
    ep_only     = "false"

  strings:
    $a = { 94 BC ?? ?? ?? 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 }

  condition:
    $a
}