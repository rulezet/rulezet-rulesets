rule TTP_XOR_MULT_DOSStub_6fb6 {
  strings:
    $key_6fb6 = { 3b de [2] 4f c6 [2] 08 c4 [2] 4f d5 [2] 01 d9 [2] 0d d3 [2] 1a d8 [2] 01 96 [2] 3c }

  condition:
    any of them
}