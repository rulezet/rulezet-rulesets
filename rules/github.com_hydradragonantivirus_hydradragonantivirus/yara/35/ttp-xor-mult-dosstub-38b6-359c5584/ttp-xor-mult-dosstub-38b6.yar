rule TTP_XOR_MULT_DOSStub_38b6 {
  strings:
    $key_38b6 = { 6c de [2] 18 c6 [2] 5f c4 [2] 18 d5 [2] 56 d9 [2] 5a d3 [2] 4d d8 [2] 56 96 [2] 6b }

  condition:
    any of them
}