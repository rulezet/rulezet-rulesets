rule TTP_XOR_MULT_DOSStub_aa36 {
  strings:
    $key_aa36 = { fe 5e [2] 8a 46 [2] cd 44 [2] 8a 55 [2] c4 59 [2] c8 53 [2] df 58 [2] c4 16 [2] f9 }

  condition:
    any of them
}