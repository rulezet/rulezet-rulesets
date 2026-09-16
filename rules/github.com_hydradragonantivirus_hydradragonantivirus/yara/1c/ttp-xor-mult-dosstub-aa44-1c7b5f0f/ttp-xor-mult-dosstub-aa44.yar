rule TTP_XOR_MULT_DOSStub_aa44 {
  strings:
    $key_aa44 = { fe 2c [2] 8a 34 [2] cd 36 [2] 8a 27 [2] c4 2b [2] c8 21 [2] df 2a [2] c4 64 [2] f9 }

  condition:
    any of them
}