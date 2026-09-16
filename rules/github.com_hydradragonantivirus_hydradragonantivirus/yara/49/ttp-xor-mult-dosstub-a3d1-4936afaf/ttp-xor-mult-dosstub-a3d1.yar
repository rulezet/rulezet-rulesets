rule TTP_XOR_MULT_DOSStub_a3d1 {
  strings:
    $key_a3d1 = { f7 b9 [2] 83 a1 [2] c4 a3 [2] 83 b2 [2] cd be [2] c1 b4 [2] d6 bf [2] cd f1 [2] f0 }

  condition:
    any of them
}