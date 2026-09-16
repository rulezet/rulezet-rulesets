rule TTP_XOR_MULT_DOSStub_43d4 {
  strings:
    $key_43d4 = { 17 bc [2] 63 a4 [2] 24 a6 [2] 63 b7 [2] 2d bb [2] 21 b1 [2] 36 ba [2] 2d f4 [2] 10 }

  condition:
    any of them
}