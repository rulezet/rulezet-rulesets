rule TTP_XOR_MULT_DOSStub_a389 {
  strings:
    $key_a389 = { f7 e1 [2] 83 f9 [2] c4 fb [2] 83 ea [2] cd e6 [2] c1 ec [2] d6 e7 [2] cd a9 [2] f0 }

  condition:
    any of them
}