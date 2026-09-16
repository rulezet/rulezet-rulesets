rule TTP_XOR_MULT_DOSStub_18b6 {
  strings:
    $key_18b6 = { 4c de [2] 38 c6 [2] 7f c4 [2] 38 d5 [2] 76 d9 [2] 7a d3 [2] 6d d8 [2] 76 96 [2] 4b }

  condition:
    any of them
}