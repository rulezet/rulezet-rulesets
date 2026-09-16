rule TTP_XOR_MULT_DOSStub_62b6 {
  strings:
    $key_62b6 = { 36 de [2] 42 c6 [2] 05 c4 [2] 42 d5 [2] 0c d9 [2] 00 d3 [2] 17 d8 [2] 0c 96 [2] 31 }

  condition:
    any of them
}