rule TTP_XOR_MULT_DOSStub_b3d1 {
  strings:
    $key_b3d1 = { e7 b9 [2] 93 a1 [2] d4 a3 [2] 93 b2 [2] dd be [2] d1 b4 [2] c6 bf [2] dd f1 [2] e0 }

  condition:
    any of them
}