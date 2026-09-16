rule TTP_XOR_MULT_DOSStub_a392 {
  strings:
    $key_a392 = { f7 fa [2] 83 e2 [2] c4 e0 [2] 83 f1 [2] cd fd [2] c1 f7 [2] d6 fc [2] cd b2 [2] f0 }

  condition:
    any of them
}