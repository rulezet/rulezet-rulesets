rule TTP_XOR_MULT_DOSStub_a3d9 {
  strings:
    $key_a3d9 = { f7 b1 [2] 83 a9 [2] c4 ab [2] 83 ba [2] cd b6 [2] c1 bc [2] d6 b7 [2] cd f9 [2] f0 }

  condition:
    any of them
}