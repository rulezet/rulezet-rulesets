rule TTP_XOR_MULT_DOSStub_a340 {
  strings:
    $key_a340 = { f7 28 [2] 83 30 [2] c4 32 [2] 83 23 [2] cd 2f [2] c1 25 [2] d6 2e [2] cd 60 [2] f0 }

  condition:
    any of them
}