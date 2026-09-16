rule TTP_XOR_MULT_DOSStub_b2d4 {
  strings:
    $key_b2d4 = { e6 bc [2] 92 a4 [2] d5 a6 [2] 92 b7 [2] dc bb [2] d0 b1 [2] c7 ba [2] dc f4 [2] e1 }

  condition:
    any of them
}