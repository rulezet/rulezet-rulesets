rule TTP_XOR_MULT_DOSStub_43c6 {
  strings:
    $key_43c6 = { 17 ae [2] 63 b6 [2] 24 b4 [2] 63 a5 [2] 2d a9 [2] 21 a3 [2] 36 a8 [2] 2d e6 [2] 10 }

  condition:
    any of them
}