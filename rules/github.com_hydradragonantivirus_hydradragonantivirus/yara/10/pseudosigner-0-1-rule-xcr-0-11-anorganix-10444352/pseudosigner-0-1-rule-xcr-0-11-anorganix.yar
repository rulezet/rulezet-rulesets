import "pe"
rule __PseudoSigner_0_1_rule__XCR_0_11______Anorganix {
  strings:
    $a0 = { 60 8B F0 33 DB 83 C3 01 83 C0 01 E9 }

  condition:
    $a0 at pe.entry_point
}