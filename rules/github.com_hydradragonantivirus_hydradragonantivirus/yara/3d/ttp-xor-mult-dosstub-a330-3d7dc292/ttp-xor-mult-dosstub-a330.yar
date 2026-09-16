rule TTP_XOR_MULT_DOSStub_a330 {
  strings:
    $key_a330 = { f7 58 [2] 83 40 [2] c4 42 [2] 83 53 [2] cd 5f [2] c1 55 [2] d6 5e [2] cd 10 [2] f0 }

  condition:
    any of them
}