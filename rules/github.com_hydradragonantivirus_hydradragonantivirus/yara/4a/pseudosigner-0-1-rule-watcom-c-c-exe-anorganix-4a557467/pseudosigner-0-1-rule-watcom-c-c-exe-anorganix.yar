import "pe"
rule __PseudoSigner_0_1_rule__WATCOM_C_C___EXE______Anorganix {
  strings:
    $a0 = { E9 00 00 00 00 90 90 90 90 57 41 E9 }

  condition:
    $a0 at pe.entry_point
}