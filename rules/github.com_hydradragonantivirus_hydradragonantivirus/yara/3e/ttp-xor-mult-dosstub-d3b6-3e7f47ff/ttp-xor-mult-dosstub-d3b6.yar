rule TTP_XOR_MULT_DOSStub_d3b6 {
  strings:
    $key_d3b6 = { 87 de [2] f3 c6 [2] b4 c4 [2] f3 d5 [2] bd d9 [2] b1 d3 [2] a6 d8 [2] bd 96 [2] 80 }

  condition:
    any of them
}