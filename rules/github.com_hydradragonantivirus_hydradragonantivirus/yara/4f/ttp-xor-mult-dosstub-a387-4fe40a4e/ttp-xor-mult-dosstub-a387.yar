rule TTP_XOR_MULT_DOSStub_a387 {
  strings:
    $key_a387 = { f7 ef [2] 83 f7 [2] c4 f5 [2] 83 e4 [2] cd e8 [2] c1 e2 [2] d6 e9 [2] cd a7 [2] f0 }

  condition:
    any of them
}