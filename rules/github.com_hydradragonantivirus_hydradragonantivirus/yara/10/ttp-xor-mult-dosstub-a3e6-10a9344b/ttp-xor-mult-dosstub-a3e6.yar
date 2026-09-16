rule TTP_XOR_MULT_DOSStub_a3e6 {
  strings:
    $key_a3e6 = { f7 8e [2] 83 96 [2] c4 94 [2] 83 85 [2] cd 89 [2] c1 83 [2] d6 88 [2] cd c6 [2] f0 }

  condition:
    any of them
}