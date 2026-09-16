rule TTP_XOR_MULT_DOSStub_aa18 {
  strings:
    $key_aa18 = { fe 70 [2] 8a 68 [2] cd 6a [2] 8a 7b [2] c4 77 [2] c8 7d [2] df 76 [2] c4 38 [2] f9 }

  condition:
    any of them
}