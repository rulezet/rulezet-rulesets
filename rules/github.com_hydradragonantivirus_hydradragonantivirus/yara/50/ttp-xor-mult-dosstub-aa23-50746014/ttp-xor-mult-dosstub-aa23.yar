rule TTP_XOR_MULT_DOSStub_aa23 {
  strings:
    $key_aa23 = { fe 4b [2] 8a 53 [2] cd 51 [2] 8a 40 [2] c4 4c [2] c8 46 [2] df 4d [2] c4 03 [2] f9 }

  condition:
    any of them
}