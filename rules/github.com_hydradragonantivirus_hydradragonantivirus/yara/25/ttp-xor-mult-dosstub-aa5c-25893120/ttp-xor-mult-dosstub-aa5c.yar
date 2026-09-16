rule TTP_XOR_MULT_DOSStub_aa5c {
  strings:
    $key_aa5c = { fe 34 [2] 8a 2c [2] cd 2e [2] 8a 3f [2] c4 33 [2] c8 39 [2] df 32 [2] c4 7c [2] f9 }

  condition:
    any of them
}