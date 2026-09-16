rule TTP_XOR_MULT_DOSStub_aa05 {
  strings:
    $key_aa05 = { fe 6d [2] 8a 75 [2] cd 77 [2] 8a 66 [2] c4 6a [2] c8 60 [2] df 6b [2] c4 25 [2] f9 }

  condition:
    any of them
}