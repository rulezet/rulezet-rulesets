rule TTP_XOR_MULT_DOSStub_07b6 {
  strings:
    $key_07b6 = { 53 de [2] 27 c6 [2] 60 c4 [2] 27 d5 [2] 69 d9 [2] 65 d3 [2] 72 d8 [2] 69 96 [2] 54 }

  condition:
    any of them
}