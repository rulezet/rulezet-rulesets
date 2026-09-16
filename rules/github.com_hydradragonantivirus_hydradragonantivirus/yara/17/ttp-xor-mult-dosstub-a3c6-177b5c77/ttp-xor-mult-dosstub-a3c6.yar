rule TTP_XOR_MULT_DOSStub_a3c6 {
  strings:
    $key_a3c6 = { f7 ae [2] 83 b6 [2] c4 b4 [2] 83 a5 [2] cd a9 [2] c1 a3 [2] d6 a8 [2] cd e6 [2] f0 }

  condition:
    any of them
}