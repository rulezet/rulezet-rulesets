rule TTP_XOR_MULT_DOSStub_43b6 {
  strings:
    $key_43b6 = { 17 de [2] 63 c6 [2] 24 c4 [2] 63 d5 [2] 2d d9 [2] 21 d3 [2] 36 d8 [2] 2d 96 [2] 10 }

  condition:
    any of them
}