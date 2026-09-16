rule TTP_XOR_MULT_DOSStub_aa04 {
  strings:
    $key_aa04 = { fe 6c [2] 8a 74 [2] cd 76 [2] 8a 67 [2] c4 6b [2] c8 61 [2] df 6a [2] c4 24 [2] f9 }

  condition:
    any of them
}