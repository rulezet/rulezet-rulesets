rule TTP_XOR_MULT_DOSStub_aa77 {
  strings:
    $key_aa77 = { fe 1f [2] 8a 07 [2] cd 05 [2] 8a 14 [2] c4 18 [2] c8 12 [2] df 19 [2] c4 57 [2] f9 }

  condition:
    any of them
}