rule TTP_XOR_MULT_DOSStub_aaf1 {
  strings:
    $key_aaf1 = { fe 99 [2] 8a 81 [2] cd 83 [2] 8a 92 [2] c4 9e [2] c8 94 [2] df 9f [2] c4 d1 [2] f9 }

  condition:
    any of them
}