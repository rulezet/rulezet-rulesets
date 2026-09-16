rule TTP_XOR_MULT_DOSStub_a3c8 {
  strings:
    $key_a3c8 = { f7 a0 [2] 83 b8 [2] c4 ba [2] 83 ab [2] cd a7 [2] c1 ad [2] d6 a6 [2] cd e8 [2] f0 }

  condition:
    any of them
}