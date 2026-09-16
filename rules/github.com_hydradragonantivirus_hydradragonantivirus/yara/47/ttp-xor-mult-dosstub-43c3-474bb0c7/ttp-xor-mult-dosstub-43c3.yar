rule TTP_XOR_MULT_DOSStub_43c3 {
  strings:
    $key_43c3 = { 17 ab [2] 63 b3 [2] 24 b1 [2] 63 a0 [2] 2d ac [2] 21 a6 [2] 36 ad [2] 2d e3 [2] 10 }

  condition:
    any of them
}