rule TTP_XOR_MULT_DOSStub_22b6 {
  strings:
    $key_22b6 = { 76 de [2] 02 c6 [2] 45 c4 [2] 02 d5 [2] 4c d9 [2] 40 d3 [2] 57 d8 [2] 4c 96 [2] 71 }

  condition:
    any of them
}