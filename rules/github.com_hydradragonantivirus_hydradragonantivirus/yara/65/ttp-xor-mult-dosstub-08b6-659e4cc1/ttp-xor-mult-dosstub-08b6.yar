rule TTP_XOR_MULT_DOSStub_08b6 {
  strings:
    $key_08b6 = { 5c de [2] 28 c6 [2] 6f c4 [2] 28 d5 [2] 66 d9 [2] 6a d3 [2] 7d d8 [2] 66 96 [2] 5b }

  condition:
    any of them
}