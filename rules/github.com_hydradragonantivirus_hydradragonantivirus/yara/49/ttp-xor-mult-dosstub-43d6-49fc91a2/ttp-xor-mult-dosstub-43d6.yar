rule TTP_XOR_MULT_DOSStub_43d6 {
  strings:
    $key_43d6 = { 17 be [2] 63 a6 [2] 24 a4 [2] 63 b5 [2] 2d b9 [2] 21 b3 [2] 36 b8 [2] 2d f6 [2] 10 }

  condition:
    any of them
}