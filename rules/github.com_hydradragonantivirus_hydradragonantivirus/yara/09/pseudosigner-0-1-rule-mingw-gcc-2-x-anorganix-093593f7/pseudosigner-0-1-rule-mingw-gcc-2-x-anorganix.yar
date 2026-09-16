import "pe"
rule __PseudoSigner_0_1_rule__MinGW_GCC_2_x______Anorganix {
  strings:
    $a0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9 }

  condition:
    $a0 at pe.entry_point
}