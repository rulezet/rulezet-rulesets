rule TTP_XOR_MULT_DOSStub_aae3 {
  strings:
    $key_aae3 = { fe 8b [2] 8a 93 [2] cd 91 [2] 8a 80 [2] c4 8c [2] c8 86 [2] df 8d [2] c4 c3 [2] f9 }

  condition:
    any of them
}