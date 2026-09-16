rule TTP_XOR_MULT_DOSStub_aa10 {
  strings:
    $key_aa10 = { fe 78 [2] 8a 60 [2] cd 62 [2] 8a 73 [2] c4 7f [2] c8 75 [2] df 7e [2] c4 30 [2] f9 }

  condition:
    any of them
}