rule TTP_XOR_MULT_DOSStub_aae8 {
  strings:
    $key_aae8 = { fe 80 [2] 8a 98 [2] cd 9a [2] 8a 8b [2] c4 87 [2] c8 8d [2] df 86 [2] c4 c8 [2] f9 }

  condition:
    any of them
}