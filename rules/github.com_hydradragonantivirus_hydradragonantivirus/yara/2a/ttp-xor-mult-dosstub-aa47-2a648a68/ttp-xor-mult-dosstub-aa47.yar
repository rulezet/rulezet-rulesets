rule TTP_XOR_MULT_DOSStub_aa47 {
  strings:
    $key_aa47 = { fe 2f [2] 8a 37 [2] cd 35 [2] 8a 24 [2] c4 28 [2] c8 22 [2] df 29 [2] c4 67 [2] f9 }

  condition:
    any of them
}