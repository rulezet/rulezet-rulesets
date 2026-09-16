rule TTP_XOR_MULT_DOSStub_36b6 {
  strings:
    $key_36b6 = { 62 de [2] 16 c6 [2] 51 c4 [2] 16 d5 [2] 58 d9 [2] 54 d3 [2] 43 d8 [2] 58 96 [2] 65 }

  condition:
    any of them
}