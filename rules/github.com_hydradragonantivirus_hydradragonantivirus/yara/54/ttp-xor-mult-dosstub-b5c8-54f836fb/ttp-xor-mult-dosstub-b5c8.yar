rule TTP_XOR_MULT_DOSStub_b5c8 {
  strings:
    $key_b5c8 = { e1 a0 [2] 95 b8 [2] d2 ba [2] 95 ab [2] db a7 [2] d7 ad [2] c0 a6 [2] db e8 [2] e6 }

  condition:
    any of them
}