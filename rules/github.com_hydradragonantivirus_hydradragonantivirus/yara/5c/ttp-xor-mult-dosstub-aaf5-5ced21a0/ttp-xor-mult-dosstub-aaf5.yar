rule TTP_XOR_MULT_DOSStub_aaf5 {
  strings:
    $key_aaf5 = { fe 9d [2] 8a 85 [2] cd 87 [2] 8a 96 [2] c4 9a [2] c8 90 [2] df 9b [2] c4 d5 [2] f9 }

  condition:
    any of them
}