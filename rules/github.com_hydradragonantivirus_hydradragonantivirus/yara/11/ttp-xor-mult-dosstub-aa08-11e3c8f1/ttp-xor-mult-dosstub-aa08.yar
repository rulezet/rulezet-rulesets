rule TTP_XOR_MULT_DOSStub_aa08 {
  strings:
    $key_aa08 = { fe 60 [2] 8a 78 [2] cd 7a [2] 8a 6b [2] c4 67 [2] c8 6d [2] df 66 [2] c4 28 [2] f9 }

  condition:
    any of them
}