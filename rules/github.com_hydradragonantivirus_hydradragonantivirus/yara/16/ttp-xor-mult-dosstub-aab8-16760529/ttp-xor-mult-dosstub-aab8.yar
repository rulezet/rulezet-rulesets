rule TTP_XOR_MULT_DOSStub_aab8 {
  strings:
    $key_aab8 = { fe d0 [2] 8a c8 [2] cd ca [2] 8a db [2] c4 d7 [2] c8 dd [2] df d6 [2] c4 98 [2] f9 }

  condition:
    any of them
}