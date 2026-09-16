rule TTP_XOR_MULT_DOSStub_aafd {
  strings:
    $key_aafd = { fe 95 [2] 8a 8d [2] cd 8f [2] 8a 9e [2] c4 92 [2] c8 98 [2] df 93 [2] c4 dd [2] f9 }

  condition:
    any of them
}