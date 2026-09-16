rule TTP_XOR_MULT_DOSStub_a3b5 {
  strings:
    $key_a3b5 = { f7 dd [2] 83 c5 [2] c4 c7 [2] 83 d6 [2] cd da [2] c1 d0 [2] d6 db [2] cd 95 [2] f0 }

  condition:
    any of them
}