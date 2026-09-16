rule TTP_XOR_MULT_DOSStub_a38d {
  strings:
    $key_a38d = { f7 e5 [2] 83 fd [2] c4 ff [2] 83 ee [2] cd e2 [2] c1 e8 [2] d6 e3 [2] cd ad [2] f0 }

  condition:
    any of them
}