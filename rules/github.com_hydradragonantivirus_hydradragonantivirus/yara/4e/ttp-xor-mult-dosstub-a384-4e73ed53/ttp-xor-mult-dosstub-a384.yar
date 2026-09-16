rule TTP_XOR_MULT_DOSStub_a384 {
  strings:
    $key_a384 = { f7 ec [2] 83 f4 [2] c4 f6 [2] 83 e7 [2] cd eb [2] c1 e1 [2] d6 ea [2] cd a4 [2] f0 }

  condition:
    any of them
}