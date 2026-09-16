rule TTP_XOR_MULT_DOSStub_b3c8 {
  strings:
    $key_b3c8 = { e7 a0 [2] 93 b8 [2] d4 ba [2] 93 ab [2] dd a7 [2] d1 ad [2] c6 a6 [2] dd e8 [2] e0 }

  condition:
    any of them
}