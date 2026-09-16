rule TTP_XOR_MULT_DOSStub_60c0 {
  strings:
    $key_60c0 = { 34 a8 [2] 40 b0 [2] 07 b2 [2] 40 a3 [2] 0e af [2] 02 a5 [2] 15 ae [2] 0e e0 [2] 33 }

  condition:
    any of them
}