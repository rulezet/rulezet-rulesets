rule TTP_XOR_MULT_DOSStub_aaf0 {
  strings:
    $key_aaf0 = { fe 98 [2] 8a 80 [2] cd 82 [2] 8a 93 [2] c4 9f [2] c8 95 [2] df 9e [2] c4 d0 [2] f9 }

  condition:
    any of them
}