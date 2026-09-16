import "pe"
rule __PseudoSigner_0_1_rule__REALBasic______Anorganix {
  strings:
    $a0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9 }

  condition:
    $a0 at pe.entry_point
}