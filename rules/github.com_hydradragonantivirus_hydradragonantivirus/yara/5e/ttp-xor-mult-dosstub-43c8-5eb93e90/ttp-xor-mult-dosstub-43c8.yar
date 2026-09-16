rule TTP_XOR_MULT_DOSStub_43c8 {
  strings:
    $key_43c8 = { 17 a0 [2] 63 b8 [2] 24 ba [2] 63 ab [2] 2d a7 [2] 21 ad [2] 36 a6 [2] 2d e8 [2] 10 }

  condition:
    any of them
}