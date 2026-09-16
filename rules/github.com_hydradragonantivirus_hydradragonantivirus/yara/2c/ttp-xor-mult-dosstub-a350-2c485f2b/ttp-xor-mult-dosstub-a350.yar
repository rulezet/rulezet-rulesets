rule TTP_XOR_MULT_DOSStub_a350 {
  strings:
    $key_a350 = { f7 38 [2] 83 20 [2] c4 22 [2] 83 33 [2] cd 3f [2] c1 35 [2] d6 3e [2] cd 70 [2] f0 }

  condition:
    any of them
}