rule TTP_XOR_MULT_DOSStub_aafe {
  strings:
    $key_aafe = { fe 96 [2] 8a 8e [2] cd 8c [2] 8a 9d [2] c4 91 [2] c8 9b [2] df 90 [2] c4 de [2] f9 }

  condition:
    any of them
}