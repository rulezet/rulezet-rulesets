rule TTP_XOR_MULT_DOSStub_aa16 {
  strings:
    $key_aa16 = { fe 7e [2] 8a 66 [2] cd 64 [2] 8a 75 [2] c4 79 [2] c8 73 [2] df 78 [2] c4 36 [2] f9 }

  condition:
    any of them
}