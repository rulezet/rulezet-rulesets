rule TTP_XOR_MULT_DOSStub_67b6 {
  strings:
    $key_67b6 = { 33 de [2] 47 c6 [2] 00 c4 [2] 47 d5 [2] 09 d9 [2] 05 d3 [2] 12 d8 [2] 09 96 [2] 34 }

  condition:
    any of them
}