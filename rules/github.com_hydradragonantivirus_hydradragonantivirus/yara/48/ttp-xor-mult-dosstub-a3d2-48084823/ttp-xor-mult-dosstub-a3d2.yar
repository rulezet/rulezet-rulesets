rule TTP_XOR_MULT_DOSStub_a3d2 {
  strings:
    $key_a3d2 = { f7 ba [2] 83 a2 [2] c4 a0 [2] 83 b1 [2] cd bd [2] c1 b7 [2] d6 bc [2] cd f2 [2] f0 }

  condition:
    any of them
}