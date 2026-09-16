rule TTP_XOR_MULT_DOSStub_4fb6 {
  strings:
    $key_4fb6 = { 1b de [2] 6f c6 [2] 28 c4 [2] 6f d5 [2] 21 d9 [2] 2d d3 [2] 3a d8 [2] 21 96 [2] 1c }

  condition:
    any of them
}