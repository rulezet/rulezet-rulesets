rule TTP_XOR_MULT_DOSStub_aaf9 {
  strings:
    $key_aaf9 = { fe 91 [2] 8a 89 [2] cd 8b [2] 8a 9a [2] c4 96 [2] c8 9c [2] df 97 [2] c4 d9 [2] f9 }

  condition:
    any of them
}