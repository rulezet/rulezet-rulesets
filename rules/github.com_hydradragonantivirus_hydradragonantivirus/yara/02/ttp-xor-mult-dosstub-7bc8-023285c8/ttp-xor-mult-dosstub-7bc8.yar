rule TTP_XOR_MULT_DOSStub_7bc8 {
  strings:
    $key_7bc8 = { 2f a0 [2] 5b b8 [2] 1c ba [2] 5b ab [2] 15 a7 [2] 19 ad [2] 0e a6 [2] 15 e8 [2] 28 }

  condition:
    any of them
}