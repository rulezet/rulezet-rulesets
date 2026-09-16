rule TTP_XOR_MULT_DOSStub_a360 {
  strings:
    $key_a360 = { f7 08 [2] 83 10 [2] c4 12 [2] 83 03 [2] cd 0f [2] c1 05 [2] d6 0e [2] cd 40 [2] f0 }

  condition:
    any of them
}