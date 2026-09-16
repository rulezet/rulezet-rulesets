import "pe"
rule __PseudoSigner_0_1_rule__FSG_1_31______Anorganix {
  strings:
    $a0 = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9 }

  condition:
    $a0 at pe.entry_point
}