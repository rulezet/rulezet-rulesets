rule TTP_XOR_MULT_DOSStub_43c5 {
  strings:
    $key_43c5 = { 17 ad [2] 63 b5 [2] 24 b7 [2] 63 a6 [2] 2d aa [2] 21 a0 [2] 36 ab [2] 2d e5 [2] 10 }

  condition:
    any of them
}