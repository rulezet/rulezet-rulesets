rule TTP_XOR_MULT_DOSStub_aa7b {
  strings:
    $key_aa7b = { fe 13 [2] 8a 0b [2] cd 09 [2] 8a 18 [2] c4 14 [2] c8 1e [2] df 15 [2] c4 5b [2] f9 }

  condition:
    any of them
}