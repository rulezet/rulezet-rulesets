rule TTP_XOR_MULT_DOSStub_68b6 {
  strings:
    $key_68b6 = { 3c de [2] 48 c6 [2] 0f c4 [2] 48 d5 [2] 06 d9 [2] 0a d3 [2] 1d d8 [2] 06 96 [2] 3b }

  condition:
    any of them
}