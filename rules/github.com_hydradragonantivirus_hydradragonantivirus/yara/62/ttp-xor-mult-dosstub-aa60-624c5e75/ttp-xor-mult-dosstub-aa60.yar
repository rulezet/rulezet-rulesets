rule TTP_XOR_MULT_DOSStub_aa60 {
  strings:
    $key_aa60 = { fe 08 [2] 8a 10 [2] cd 12 [2] 8a 03 [2] c4 0f [2] c8 05 [2] df 0e [2] c4 40 [2] f9 }

  condition:
    any of them
}