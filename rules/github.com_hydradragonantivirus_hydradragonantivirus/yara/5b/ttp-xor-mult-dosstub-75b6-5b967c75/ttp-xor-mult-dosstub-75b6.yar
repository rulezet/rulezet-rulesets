rule TTP_XOR_MULT_DOSStub_75b6 {
  strings:
    $key_75b6 = { 21 de [2] 55 c6 [2] 12 c4 [2] 55 d5 [2] 1b d9 [2] 17 d3 [2] 00 d8 [2] 1b 96 [2] 26 }

  condition:
    any of them
}