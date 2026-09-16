rule TTP_XOR_MULT_DOSStub_aa17 {
  strings:
    $key_aa17 = { fe 7f [2] 8a 67 [2] cd 65 [2] 8a 74 [2] c4 78 [2] c8 72 [2] df 79 [2] c4 37 [2] f9 }

  condition:
    any of them
}