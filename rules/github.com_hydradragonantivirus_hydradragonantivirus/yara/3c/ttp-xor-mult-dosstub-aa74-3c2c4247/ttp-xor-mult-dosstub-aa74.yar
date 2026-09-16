rule TTP_XOR_MULT_DOSStub_aa74 {
  strings:
    $key_aa74 = { fe 1c [2] 8a 04 [2] cd 06 [2] 8a 17 [2] c4 1b [2] c8 11 [2] df 1a [2] c4 54 [2] f9 }

  condition:
    any of them
}