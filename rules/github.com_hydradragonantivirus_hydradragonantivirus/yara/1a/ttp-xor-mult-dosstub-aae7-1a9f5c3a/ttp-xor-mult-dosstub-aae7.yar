rule TTP_XOR_MULT_DOSStub_aae7 {
  strings:
    $key_aae7 = { fe 8f [2] 8a 97 [2] cd 95 [2] 8a 84 [2] c4 88 [2] c8 82 [2] df 89 [2] c4 c7 [2] f9 }

  condition:
    any of them
}