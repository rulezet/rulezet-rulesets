rule TTP_XOR_MULT_DOSStub_aa76 {
  strings:
    $key_aa76 = { fe 1e [2] 8a 06 [2] cd 04 [2] 8a 15 [2] c4 19 [2] c8 13 [2] df 18 [2] c4 56 [2] f9 }

  condition:
    any of them
}