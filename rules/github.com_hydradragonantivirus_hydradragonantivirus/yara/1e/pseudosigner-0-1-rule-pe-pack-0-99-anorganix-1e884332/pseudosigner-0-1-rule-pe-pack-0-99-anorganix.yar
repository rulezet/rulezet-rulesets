import "pe"
rule __PseudoSigner_0_1_rule__PE_Pack_0_99______Anorganix {
  strings:
    $a0 = { 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A E9 }

  condition:
    $a0 at pe.entry_point
}