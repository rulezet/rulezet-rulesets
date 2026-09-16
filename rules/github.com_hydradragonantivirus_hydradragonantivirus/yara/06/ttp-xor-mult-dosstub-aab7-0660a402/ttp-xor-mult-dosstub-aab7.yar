rule TTP_XOR_MULT_DOSStub_aab7 {
  strings:
    $key_aab7 = { fe df [2] 8a c7 [2] cd c5 [2] 8a d4 [2] c4 d8 [2] c8 d2 [2] df d9 [2] c4 97 [2] f9 }

  condition:
    any of them
}