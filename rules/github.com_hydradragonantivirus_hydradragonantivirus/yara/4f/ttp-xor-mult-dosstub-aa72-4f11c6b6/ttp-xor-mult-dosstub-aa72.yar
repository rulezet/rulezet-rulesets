rule TTP_XOR_MULT_DOSStub_aa72 {
  strings:
    $key_aa72 = { fe 1a [2] 8a 02 [2] cd 00 [2] 8a 11 [2] c4 1d [2] c8 17 [2] df 1c [2] c4 52 [2] f9 }

  condition:
    any of them
}