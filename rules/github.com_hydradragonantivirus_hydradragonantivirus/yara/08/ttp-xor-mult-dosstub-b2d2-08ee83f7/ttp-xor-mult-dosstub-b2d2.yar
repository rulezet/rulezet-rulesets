rule TTP_XOR_MULT_DOSStub_b2d2 {
  strings:
    $key_b2d2 = { e6 ba [2] 92 a2 [2] d5 a0 [2] 92 b1 [2] dc bd [2] d0 b7 [2] c7 bc [2] dc f2 [2] e1 }

  condition:
    any of them
}