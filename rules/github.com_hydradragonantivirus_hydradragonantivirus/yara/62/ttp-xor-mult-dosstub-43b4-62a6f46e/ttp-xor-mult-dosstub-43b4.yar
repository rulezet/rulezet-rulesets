rule TTP_XOR_MULT_DOSStub_43b4 {
  strings:
    $key_43b4 = { 17 dc [2] 63 c4 [2] 24 c6 [2] 63 d7 [2] 2d db [2] 21 d1 [2] 36 da [2] 2d 94 [2] 10 }

  condition:
    any of them
}