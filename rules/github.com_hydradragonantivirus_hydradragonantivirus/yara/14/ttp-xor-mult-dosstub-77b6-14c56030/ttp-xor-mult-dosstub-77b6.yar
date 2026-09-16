rule TTP_XOR_MULT_DOSStub_77b6 {
  strings:
    $key_77b6 = { 23 de [2] 57 c6 [2] 10 c4 [2] 57 d5 [2] 19 d9 [2] 15 d3 [2] 02 d8 [2] 19 96 [2] 24 }

  condition:
    any of them
}