rule TTP_XOR_MULT_DOSStub_a627 {
  strings:
    $key_a627 = { f2 4f [2] 86 57 [2] c1 55 [2] 86 44 [2] c8 48 [2] c4 42 [2] d3 49 [2] c8 07 [2] f5 }

  condition:
    any of them
}