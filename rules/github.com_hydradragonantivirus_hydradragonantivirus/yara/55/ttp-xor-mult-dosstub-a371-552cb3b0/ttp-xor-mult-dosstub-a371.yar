rule TTP_XOR_MULT_DOSStub_a371 {
  strings:
    $key_a371 = { f7 19 [2] 83 01 [2] c4 03 [2] 83 12 [2] cd 1e [2] c1 14 [2] d6 1f [2] cd 51 [2] f0 }

  condition:
    any of them
}