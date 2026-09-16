rule TTP_XOR_MULT_DOSStub_aa52 {
  strings:
    $key_aa52 = { fe 3a [2] 8a 22 [2] cd 20 [2] 8a 31 [2] c4 3d [2] c8 37 [2] df 3c [2] c4 72 [2] f9 }

  condition:
    any of them
}