rule TTP_XOR_MULT_DOSStub_aa5b {
  strings:
    $key_aa5b = { fe 33 [2] 8a 2b [2] cd 29 [2] 8a 38 [2] c4 34 [2] c8 3e [2] df 35 [2] c4 7b [2] f9 }

  condition:
    any of them
}