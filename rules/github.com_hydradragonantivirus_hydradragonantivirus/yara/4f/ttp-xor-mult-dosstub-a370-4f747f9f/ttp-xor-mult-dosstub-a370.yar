rule TTP_XOR_MULT_DOSStub_a370 {
  strings:
    $key_a370 = { f7 18 [2] 83 00 [2] c4 02 [2] 83 13 [2] cd 1f [2] c1 15 [2] d6 1e [2] cd 50 [2] f0 }

  condition:
    any of them
}