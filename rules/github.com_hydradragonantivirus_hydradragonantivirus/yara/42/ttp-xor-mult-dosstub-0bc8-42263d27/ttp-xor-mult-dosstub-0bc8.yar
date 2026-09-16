rule TTP_XOR_MULT_DOSStub_0bc8 {
  strings:
    $key_0bc8 = { 5f a0 [2] 2b b8 [2] 6c ba [2] 2b ab [2] 65 a7 [2] 69 ad [2] 7e a6 [2] 65 e8 [2] 58 }

  condition:
    any of them
}