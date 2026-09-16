rule TTP_XOR_MULT_DOSStub_a3d7 {
  strings:
    $key_a3d7 = { f7 bf [2] 83 a7 [2] c4 a5 [2] 83 b4 [2] cd b8 [2] c1 b2 [2] d6 b9 [2] cd f7 [2] f0 }

  condition:
    any of them
}