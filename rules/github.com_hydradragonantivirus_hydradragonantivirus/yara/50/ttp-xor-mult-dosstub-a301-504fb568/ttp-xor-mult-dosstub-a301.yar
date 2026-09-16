rule TTP_XOR_MULT_DOSStub_a301 {
  strings:
    $key_a301 = { f7 69 [2] 83 71 [2] c4 73 [2] 83 62 [2] cd 6e [2] c1 64 [2] d6 6f [2] cd 21 [2] f0 }

  condition:
    any of them
}