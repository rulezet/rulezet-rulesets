rule TTP_XOR_MULT_DOSStub_a336 {
  strings:
    $key_a336 = { f7 5e [2] 83 46 [2] c4 44 [2] 83 55 [2] cd 59 [2] c1 53 [2] d6 58 [2] cd 16 [2] f0 }

  condition:
    any of them
}