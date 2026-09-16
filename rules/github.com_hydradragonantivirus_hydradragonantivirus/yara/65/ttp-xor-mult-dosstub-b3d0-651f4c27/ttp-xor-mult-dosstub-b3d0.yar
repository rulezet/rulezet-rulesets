rule TTP_XOR_MULT_DOSStub_b3d0 {
  strings:
    $key_b3d0 = { e7 b8 [2] 93 a0 [2] d4 a2 [2] 93 b3 [2] dd bf [2] d1 b5 [2] c6 be [2] dd f0 [2] e0 }

  condition:
    any of them
}