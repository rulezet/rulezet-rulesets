rule TTP_XOR_MULT_DOSStub_d6b6 {
  strings:
    $key_d6b6 = { 82 de [2] f6 c6 [2] b1 c4 [2] f6 d5 [2] b8 d9 [2] b4 d3 [2] a3 d8 [2] b8 96 [2] 85 }

  condition:
    any of them
}