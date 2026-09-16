rule TTP_XOR_MULT_DOSStub_49d5 {
  strings:
    $key_49d5 = { 1d bd [2] 69 a5 [2] 2e a7 [2] 69 b6 [2] 27 ba [2] 2b b0 [2] 3c bb [2] 27 f5 [2] 1a }

  condition:
    any of them
}