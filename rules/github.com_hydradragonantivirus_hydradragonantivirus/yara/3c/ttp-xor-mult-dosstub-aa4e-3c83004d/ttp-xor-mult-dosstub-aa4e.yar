rule TTP_XOR_MULT_DOSStub_aa4e {
  strings:
    $key_aa4e = { fe 26 [2] 8a 3e [2] cd 3c [2] 8a 2d [2] c4 21 [2] c8 2b [2] df 20 [2] c4 6e [2] f9 }

  condition:
    any of them
}