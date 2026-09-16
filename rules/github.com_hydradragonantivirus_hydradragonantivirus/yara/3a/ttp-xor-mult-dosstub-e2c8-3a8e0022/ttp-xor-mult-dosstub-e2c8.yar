rule TTP_XOR_MULT_DOSStub_e2c8 {
  strings:
    $key_e2c8 = { b6 a0 [2] c2 b8 [2] 85 ba [2] c2 ab [2] 8c a7 [2] 80 ad [2] 97 a6 [2] 8c e8 [2] b1 }

  condition:
    any of them
}