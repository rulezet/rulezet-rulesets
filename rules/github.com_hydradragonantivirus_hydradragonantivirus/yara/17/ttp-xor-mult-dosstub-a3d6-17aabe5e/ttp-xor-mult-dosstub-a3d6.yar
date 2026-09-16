rule TTP_XOR_MULT_DOSStub_a3d6 {
  strings:
    $key_a3d6 = { f7 be [2] 83 a6 [2] c4 a4 [2] 83 b5 [2] cd b9 [2] c1 b3 [2] d6 b8 [2] cd f6 [2] f0 }

  condition:
    any of them
}