rule TTP_XOR_MULT_DOSStub_aaf8 {
  strings:
    $key_aaf8 = { fe 90 [2] 8a 88 [2] cd 8a [2] 8a 9b [2] c4 97 [2] c8 9d [2] df 96 [2] c4 d8 [2] f9 }

  condition:
    any of them
}