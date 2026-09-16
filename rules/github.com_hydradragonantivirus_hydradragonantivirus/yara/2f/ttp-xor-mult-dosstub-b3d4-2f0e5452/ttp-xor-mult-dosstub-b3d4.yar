rule TTP_XOR_MULT_DOSStub_b3d4 {
  strings:
    $key_b3d4 = { e7 bc [2] 93 a4 [2] d4 a6 [2] 93 b7 [2] dd bb [2] d1 b1 [2] c6 ba [2] dd f4 [2] e0 }

  condition:
    any of them
}