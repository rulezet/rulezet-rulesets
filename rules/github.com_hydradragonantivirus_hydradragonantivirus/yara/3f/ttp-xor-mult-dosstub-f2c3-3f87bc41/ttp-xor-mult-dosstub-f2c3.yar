rule TTP_XOR_MULT_DOSStub_f2c3 {
  strings:
    $key_f2c3 = { a6 ab [2] d2 b3 [2] 95 b1 [2] d2 a0 [2] 9c ac [2] 90 a6 [2] 87 ad [2] 9c e3 [2] a1 }

  condition:
    any of them
}