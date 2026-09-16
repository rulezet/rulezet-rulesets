rule TTP_XOR_MULT_DOSStub_a647 {
  strings:
    $key_a647 = { f2 2f [2] 86 37 [2] c1 35 [2] 86 24 [2] c8 28 [2] c4 22 [2] d3 29 [2] c8 67 [2] f5 }

  condition:
    any of them
}