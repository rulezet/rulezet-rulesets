rule TTP_XOR_MULT_DOSStub_aa2d {
  strings:
    $key_aa2d = { fe 45 [2] 8a 5d [2] cd 5f [2] 8a 4e [2] c4 42 [2] c8 48 [2] df 43 [2] c4 0d [2] f9 }

  condition:
    any of them
}