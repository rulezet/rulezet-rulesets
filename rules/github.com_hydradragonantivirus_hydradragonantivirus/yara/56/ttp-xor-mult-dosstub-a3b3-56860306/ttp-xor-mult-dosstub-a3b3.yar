rule TTP_XOR_MULT_DOSStub_a3b3 {
  strings:
    $key_a3b3 = { f7 db [2] 83 c3 [2] c4 c1 [2] 83 d0 [2] cd dc [2] c1 d6 [2] d6 dd [2] cd 93 [2] f0 }

  condition:
    any of them
}