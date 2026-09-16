rule TTP_XOR_MULT_DOSStub_aa43 {
  strings:
    $key_aa43 = { fe 2b [2] 8a 33 [2] cd 31 [2] 8a 20 [2] c4 2c [2] c8 26 [2] df 2d [2] c4 63 [2] f9 }

  condition:
    any of them
}