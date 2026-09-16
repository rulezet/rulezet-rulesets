rule TTP_XOR_MULT_DOSStub_e6c8 {
  strings:
    $key_e6c8 = { b2 a0 [2] c6 b8 [2] 81 ba [2] c6 ab [2] 88 a7 [2] 84 ad [2] 93 a6 [2] 88 e8 [2] b5 }

  condition:
    any of them
}