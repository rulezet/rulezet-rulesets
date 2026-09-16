rule TTP_XOR_MULT_DOSStub_aa66 {
  strings:
    $key_aa66 = { fe 0e [2] 8a 16 [2] cd 14 [2] 8a 05 [2] c4 09 [2] c8 03 [2] df 08 [2] c4 46 [2] f9 }

  condition:
    any of them
}