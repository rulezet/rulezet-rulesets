rule TTP_XOR_MULT_DOSStub_4dc8 {
  strings:
    $key_4dc8 = { 19 a0 [2] 6d b8 [2] 2a ba [2] 6d ab [2] 23 a7 [2] 2f ad [2] 38 a6 [2] 23 e8 [2] 1e }

  condition:
    any of them
}