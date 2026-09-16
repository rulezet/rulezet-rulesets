rule TTP_XOR_MULT_DOSStub_43c7 {
  strings:
    $key_43c7 = { 17 af [2] 63 b7 [2] 24 b5 [2] 63 a4 [2] 2d a8 [2] 21 a2 [2] 36 a9 [2] 2d e7 [2] 10 }

  condition:
    any of them
}