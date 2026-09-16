import "pe"
rule __PseudoSigner_0_1_rule__PE_Protect_0_9______Anorganix {
  strings:
    $a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 E9 }

  condition:
    $a0 at pe.entry_point
}