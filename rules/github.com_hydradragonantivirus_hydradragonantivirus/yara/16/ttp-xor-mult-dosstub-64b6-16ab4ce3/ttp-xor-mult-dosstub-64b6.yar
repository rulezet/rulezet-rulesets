rule TTP_XOR_MULT_DOSStub_64b6 {
  strings:
    $key_64b6 = { 30 de [2] 44 c6 [2] 03 c4 [2] 44 d5 [2] 0a d9 [2] 06 d3 [2] 11 d8 [2] 0a 96 [2] 37 }

  condition:
    any of them
}