rule PEiD_01546_PECompact_v0_90_ {
  meta:
    description = "[PECompact v0.90]"
    ep_only     = "true"

  strings:
    $a = { EB 06 68 ?? ?? 40 00 C3 9C 60 BD ?? ?? 00 00 B9 02 00 00 00 B0 90 8D BD 7A 42 40 00 F3 AA 01 AD D9 43 40 00 FF B5 }

  condition:
    $a
}