rule TTP_XOR_MULT_DOSStub_aa59 {
  strings:
    $key_aa59 = { fe 31 [2] 8a 29 [2] cd 2b [2] 8a 3a [2] c4 36 [2] c8 3c [2] df 37 [2] c4 79 [2] f9 }

  condition:
    any of them
}