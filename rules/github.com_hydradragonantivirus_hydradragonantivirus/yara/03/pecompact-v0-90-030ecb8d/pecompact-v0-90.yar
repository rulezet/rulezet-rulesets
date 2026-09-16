import "pe"
rule PECompact_v0_90 {
  strings:
    $a0 = { EB 06 68 ?? ?? 40 00 C3 9C 60 BD ?? ?? 00 00 B9 02 00 00 00 B0 90 8D BD 7A 42 40 00 F3 AA 01 AD D9 43 40 00 FF B5 }

  condition:
    $a0 at pe.entry_point
}