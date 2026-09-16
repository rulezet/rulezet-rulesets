rule TTP_XOR_MULT_DOSStub_a3c5 {
  strings:
    $key_a3c5 = { f7 ad [2] 83 b5 [2] c4 b7 [2] 83 a6 [2] cd aa [2] c1 a0 [2] d6 ab [2] cd e5 [2] f0 }

  condition:
    any of them
}