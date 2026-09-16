import "pe"
rule __PseudoSigner_0_1_rule__32Lite_0_03______Anorganix {
  strings:
    $a0 = { 60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 ?? ?? ?? ?? E9 }

  condition:
    $a0 at pe.entry_point
}