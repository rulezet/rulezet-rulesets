rule TTP_XOR_MULT_DOSStub_aa27 {
  strings:
    $key_aa27 = { fe 4f [2] 8a 57 [2] cd 55 [2] 8a 44 [2] c4 48 [2] c8 42 [2] df 49 [2] c4 07 [2] f9 }

  condition:
    any of them
}