rule TTP_XOR_MULT_DOSStub_aa53 {
  strings:
    $key_aa53 = { fe 3b [2] 8a 23 [2] cd 21 [2] 8a 30 [2] c4 3c [2] c8 36 [2] df 3d [2] c4 73 [2] f9 }

  condition:
    any of them
}