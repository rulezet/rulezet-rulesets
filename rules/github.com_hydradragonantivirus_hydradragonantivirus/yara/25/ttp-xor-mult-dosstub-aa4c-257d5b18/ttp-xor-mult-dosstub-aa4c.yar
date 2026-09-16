rule TTP_XOR_MULT_DOSStub_aa4c {
  strings:
    $key_aa4c = { fe 24 [2] 8a 3c [2] cd 3e [2] 8a 2f [2] c4 23 [2] c8 29 [2] df 22 [2] c4 6c [2] f9 }

  condition:
    any of them
}