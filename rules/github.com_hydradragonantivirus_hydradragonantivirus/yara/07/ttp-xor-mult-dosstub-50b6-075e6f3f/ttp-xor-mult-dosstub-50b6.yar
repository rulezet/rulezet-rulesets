rule TTP_XOR_MULT_DOSStub_50b6 {
  strings:
    $key_50b6 = { 04 de [2] 70 c6 [2] 37 c4 [2] 70 d5 [2] 3e d9 [2] 32 d3 [2] 25 d8 [2] 3e 96 [2] 03 }

  condition:
    any of them
}