rule TTP_XOR_MULT_DOSStub_b2c3 {
  strings:
    $key_b2c3 = { e6 ab [2] 92 b3 [2] d5 b1 [2] 92 a0 [2] dc ac [2] d0 a6 [2] c7 ad [2] dc e3 [2] e1 }

  condition:
    any of them
}