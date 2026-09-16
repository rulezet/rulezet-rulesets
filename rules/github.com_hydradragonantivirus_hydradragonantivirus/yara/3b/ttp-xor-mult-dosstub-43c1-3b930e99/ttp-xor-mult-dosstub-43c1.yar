rule TTP_XOR_MULT_DOSStub_43c1 {
  strings:
    $key_43c1 = { 17 a9 [2] 63 b1 [2] 24 b3 [2] 63 a2 [2] 2d ae [2] 21 a4 [2] 36 af [2] 2d e1 [2] 10 }

  condition:
    any of them
}