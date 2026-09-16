rule TTP_XOR_MULT_DOSStub_a338 {
  strings:
    $key_a338 = { f7 50 [2] 83 48 [2] c4 4a [2] 83 5b [2] cd 57 [2] c1 5d [2] d6 56 [2] cd 18 [2] f0 }

  condition:
    any of them
}