rule TTP_XOR_MULT_DOSStub_f2c8 {
  strings:
    $key_f2c8 = { a6 a0 [2] d2 b8 [2] 95 ba [2] d2 ab [2] 9c a7 [2] 90 ad [2] 87 a6 [2] 9c e8 [2] a1 }

  condition:
    any of them
}