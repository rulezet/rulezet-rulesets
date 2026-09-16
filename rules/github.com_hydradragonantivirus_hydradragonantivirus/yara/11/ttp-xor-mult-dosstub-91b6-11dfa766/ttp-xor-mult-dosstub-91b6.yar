rule TTP_XOR_MULT_DOSStub_91b6 {
  strings:
    $key_91b6 = { c5 de [2] b1 c6 [2] f6 c4 [2] b1 d5 [2] ff d9 [2] f3 d3 [2] e4 d8 [2] ff 96 [2] c2 }

  condition:
    any of them
}