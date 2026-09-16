rule TTP_XOR_MULT_DOSStub_a3d0 {
  strings:
    $key_a3d0 = { f7 b8 [2] 83 a0 [2] c4 a2 [2] 83 b3 [2] cd bf [2] c1 b5 [2] d6 be [2] cd f0 [2] f0 }

  condition:
    any of them
}