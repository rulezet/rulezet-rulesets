rule TTP_XOR_MULT_DOSStub_aa46 {
  strings:
    $key_aa46 = { fe 2e [2] 8a 36 [2] cd 34 [2] 8a 25 [2] c4 29 [2] c8 23 [2] df 28 [2] c4 66 [2] f9 }

  condition:
    any of them
}