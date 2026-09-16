rule TTP_XOR_MULT_DOSStub_e6d9 {
  strings:
    $key_e6d9 = { b2 b1 [2] c6 a9 [2] 81 ab [2] c6 ba [2] 88 b6 [2] 84 bc [2] 93 b7 [2] 88 f9 [2] b5 }

  condition:
    any of them
}