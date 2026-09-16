rule TTP_XOR_MULT_DOSStub_a3cc {
  strings:
    $key_a3cc = { f7 a4 [2] 83 bc [2] c4 be [2] 83 af [2] cd a3 [2] c1 a9 [2] d6 a2 [2] cd ec [2] f0 }

  condition:
    any of them
}