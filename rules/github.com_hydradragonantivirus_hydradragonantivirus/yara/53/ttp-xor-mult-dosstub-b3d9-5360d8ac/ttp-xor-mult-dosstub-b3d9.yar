rule TTP_XOR_MULT_DOSStub_b3d9 {
  strings:
    $key_b3d9 = { e7 b1 [2] 93 a9 [2] d4 ab [2] 93 ba [2] dd b6 [2] d1 bc [2] c6 b7 [2] dd f9 [2] e0 }

  condition:
    any of them
}