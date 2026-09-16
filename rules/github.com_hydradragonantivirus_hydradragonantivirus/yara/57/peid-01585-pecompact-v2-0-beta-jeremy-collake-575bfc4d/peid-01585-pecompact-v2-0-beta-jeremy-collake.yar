rule PEiD_01585_PECompact_v2_0_beta____Jeremy_Collake_ {
  meta:
    description = "[PECompact v2.0 beta -> Jeremy Collake]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 }

  condition:
    $a
}