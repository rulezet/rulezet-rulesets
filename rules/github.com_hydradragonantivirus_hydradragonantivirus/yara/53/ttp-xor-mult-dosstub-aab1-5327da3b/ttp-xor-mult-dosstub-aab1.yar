rule TTP_XOR_MULT_DOSStub_aab1 {
  strings:
    $key_aab1 = { fe d9 [2] 8a c1 [2] cd c3 [2] 8a d2 [2] c4 de [2] c8 d4 [2] df df [2] c4 91 [2] f9 }

  condition:
    any of them
}