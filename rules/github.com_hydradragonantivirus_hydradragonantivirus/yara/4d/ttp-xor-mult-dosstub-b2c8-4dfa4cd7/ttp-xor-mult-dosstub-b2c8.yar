rule TTP_XOR_MULT_DOSStub_b2c8 {
  strings:
    $key_b2c8 = { e6 a0 [2] 92 b8 [2] d5 ba [2] 92 ab [2] dc a7 [2] d0 ad [2] c7 a6 [2] dc e8 [2] e1 }

  condition:
    any of them
}