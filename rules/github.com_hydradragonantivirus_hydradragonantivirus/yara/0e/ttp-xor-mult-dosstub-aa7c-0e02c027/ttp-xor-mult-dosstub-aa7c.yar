rule TTP_XOR_MULT_DOSStub_aa7c {
  strings:
    $key_aa7c = { fe 14 [2] 8a 0c [2] cd 0e [2] 8a 1f [2] c4 13 [2] c8 19 [2] df 12 [2] c4 5c [2] f9 }

  condition:
    any of them
}