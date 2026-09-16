rule TTP_XOR_MULT_DOSStub_aaa8 {
  strings:
    $key_aaa8 = { fe c0 [2] 8a d8 [2] cd da [2] 8a cb [2] c4 c7 [2] c8 cd [2] df c6 [2] c4 88 [2] f9 }

  condition:
    any of them
}