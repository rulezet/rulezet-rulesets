rule TTP_XOR_MULT_DOSStub_4bc8 {
  strings:
    $key_4bc8 = { 1f a0 [2] 6b b8 [2] 2c ba [2] 6b ab [2] 25 a7 [2] 29 ad [2] 3e a6 [2] 25 e8 [2] 18 }

  condition:
    any of them
}