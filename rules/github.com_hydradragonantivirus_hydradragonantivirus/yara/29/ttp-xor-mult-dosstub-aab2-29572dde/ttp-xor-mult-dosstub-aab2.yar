rule TTP_XOR_MULT_DOSStub_aab2 {
  strings:
    $key_aab2 = { fe da [2] 8a c2 [2] cd c0 [2] 8a d1 [2] c4 dd [2] c8 d7 [2] df dc [2] c4 92 [2] f9 }

  condition:
    any of them
}