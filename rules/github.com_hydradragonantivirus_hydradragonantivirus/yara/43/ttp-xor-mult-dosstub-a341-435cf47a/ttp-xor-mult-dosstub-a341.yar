rule TTP_XOR_MULT_DOSStub_a341 {
  strings:
    $key_a341 = { f7 29 [2] 83 31 [2] c4 33 [2] 83 22 [2] cd 2e [2] c1 24 [2] d6 2f [2] cd 61 [2] f0 }

  condition:
    any of them
}