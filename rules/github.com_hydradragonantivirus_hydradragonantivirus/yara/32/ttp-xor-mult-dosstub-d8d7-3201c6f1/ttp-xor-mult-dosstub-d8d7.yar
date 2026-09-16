rule TTP_XOR_MULT_DOSStub_d8d7 {
  strings:
    $key_d8d7 = { 8c bf [2] f8 a7 [2] bf a5 [2] f8 b4 [2] b6 b8 [2] ba b2 [2] ad b9 [2] b6 f7 [2] 8b }

  condition:
    any of them
}