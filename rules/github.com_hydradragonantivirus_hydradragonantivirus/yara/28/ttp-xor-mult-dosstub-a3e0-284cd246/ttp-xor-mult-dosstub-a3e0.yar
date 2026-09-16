rule TTP_XOR_MULT_DOSStub_a3e0 {
  strings:
    $key_a3e0 = { f7 88 [2] 83 90 [2] c4 92 [2] 83 83 [2] cd 8f [2] c1 85 [2] d6 8e [2] cd c0 [2] f0 }

  condition:
    any of them
}