rule TTP_XOR_MULT_DOSStub_aa09 {
  strings:
    $key_aa09 = { fe 61 [2] 8a 79 [2] cd 7b [2] 8a 6a [2] c4 66 [2] c8 6c [2] df 67 [2] c4 29 [2] f9 }

  condition:
    any of them
}