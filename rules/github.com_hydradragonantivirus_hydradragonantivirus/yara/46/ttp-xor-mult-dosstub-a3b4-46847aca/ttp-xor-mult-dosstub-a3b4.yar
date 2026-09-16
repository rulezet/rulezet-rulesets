rule TTP_XOR_MULT_DOSStub_a3b4 {
  strings:
    $key_a3b4 = { f7 dc [2] 83 c4 [2] c4 c6 [2] 83 d7 [2] cd db [2] c1 d1 [2] d6 da [2] cd 94 [2] f0 }

  condition:
    any of them
}