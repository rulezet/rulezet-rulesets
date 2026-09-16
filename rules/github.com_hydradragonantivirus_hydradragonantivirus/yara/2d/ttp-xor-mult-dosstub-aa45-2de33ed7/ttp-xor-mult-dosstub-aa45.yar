rule TTP_XOR_MULT_DOSStub_aa45 {
  strings:
    $key_aa45 = { fe 2d [2] 8a 35 [2] cd 37 [2] 8a 26 [2] c4 2a [2] c8 20 [2] df 2b [2] c4 65 [2] f9 }

  condition:
    any of them
}