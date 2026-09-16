rule TTP_XOR_MULT_DOSStub_43c0 {
  strings:
    $key_43c0 = { 17 a8 [2] 63 b0 [2] 24 b2 [2] 63 a3 [2] 2d af [2] 21 a5 [2] 36 ae [2] 2d e0 [2] 10 }

  condition:
    any of them
}