rule TTP_XOR_MULT_DOSStub_a6b6 {
  strings:
    $key_a6b6 = { f2 de [2] 86 c6 [2] c1 c4 [2] 86 d5 [2] c8 d9 [2] c4 d3 [2] d3 d8 [2] c8 96 [2] f5 }

  condition:
    any of them
}