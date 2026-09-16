rule TTP_XOR_MULT_DOSStub_5ab6 {
  strings:
    $key_5ab6 = { 0e de [2] 7a c6 [2] 3d c4 [2] 7a d5 [2] 34 d9 [2] 38 d3 [2] 2f d8 [2] 34 96 [2] 09 }

  condition:
    any of them
}