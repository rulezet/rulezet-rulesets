rule TTP_XOR_MULT_DOSStub_a367 {
  strings:
    $key_a367 = { f7 0f [2] 83 17 [2] c4 15 [2] 83 04 [2] cd 08 [2] c1 02 [2] d6 09 [2] cd 47 [2] f0 }

  condition:
    any of them
}