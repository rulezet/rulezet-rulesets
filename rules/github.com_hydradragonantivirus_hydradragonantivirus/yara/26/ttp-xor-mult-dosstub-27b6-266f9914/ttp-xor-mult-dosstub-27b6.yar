rule TTP_XOR_MULT_DOSStub_27b6 {
  strings:
    $key_27b6 = { 73 de [2] 07 c6 [2] 40 c4 [2] 07 d5 [2] 49 d9 [2] 45 d3 [2] 52 d8 [2] 49 96 [2] 74 }

  condition:
    any of them
}