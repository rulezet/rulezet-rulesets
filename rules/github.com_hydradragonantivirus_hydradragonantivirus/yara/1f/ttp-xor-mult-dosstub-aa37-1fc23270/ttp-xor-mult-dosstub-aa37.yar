rule TTP_XOR_MULT_DOSStub_aa37 {
  strings:
    $key_aa37 = { fe 5f [2] 8a 47 [2] cd 45 [2] 8a 54 [2] c4 58 [2] c8 52 [2] df 59 [2] c4 17 [2] f9 }

  condition:
    any of them
}