rule TTP_XOR_MULT_DOSStub_a7b6 {
  strings:
    $key_a7b6 = { f3 de [2] 87 c6 [2] c0 c4 [2] 87 d5 [2] c9 d9 [2] c5 d3 [2] d2 d8 [2] c9 96 [2] f4 }

  condition:
    any of them
}