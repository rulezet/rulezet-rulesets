rule TTP_XOR_MULT_DOSStub_31c8 {
  strings:
    $key_31c8 = { 65 a0 [2] 11 b8 [2] 56 ba [2] 11 ab [2] 5f a7 [2] 53 ad [2] 44 a6 [2] 5f e8 [2] 62 }

  condition:
    any of them
}