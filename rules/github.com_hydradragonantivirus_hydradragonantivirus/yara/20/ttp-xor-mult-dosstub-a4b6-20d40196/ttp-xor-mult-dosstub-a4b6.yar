rule TTP_XOR_MULT_DOSStub_a4b6 {
  strings:
    $key_a4b6 = { f0 de [2] 84 c6 [2] c3 c4 [2] 84 d5 [2] ca d9 [2] c6 d3 [2] d1 d8 [2] ca 96 [2] f7 }

  condition:
    any of them
}