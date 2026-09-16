rule TTP_XOR_MULT_DOSStub_aaf6 {
  strings:
    $key_aaf6 = { fe 9e [2] 8a 86 [2] cd 84 [2] 8a 95 [2] c4 99 [2] c8 93 [2] df 98 [2] c4 d6 [2] f9 }

  condition:
    any of them
}