rule TTP_XOR_MULT_DOSStub_49d2 {
  strings:
    $key_49d2 = { 1d ba [2] 69 a2 [2] 2e a0 [2] 69 b1 [2] 27 bd [2] 2b b7 [2] 3c bc [2] 27 f2 [2] 1a }

  condition:
    any of them
}