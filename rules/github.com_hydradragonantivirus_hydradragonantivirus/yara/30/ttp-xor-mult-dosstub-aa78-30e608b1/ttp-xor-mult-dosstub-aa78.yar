rule TTP_XOR_MULT_DOSStub_aa78 {
  strings:
    $key_aa78 = { fe 10 [2] 8a 08 [2] cd 0a [2] 8a 1b [2] c4 17 [2] c8 1d [2] df 16 [2] c4 58 [2] f9 }

  condition:
    any of them
}