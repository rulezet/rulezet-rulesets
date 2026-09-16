rule TTP_XOR_MULT_DOSStub_49d1 {
  strings:
    $key_49d1 = { 1d b9 [2] 69 a1 [2] 2e a3 [2] 69 b2 [2] 27 be [2] 2b b4 [2] 3c bf [2] 27 f1 [2] 1a }

  condition:
    any of them
}