rule TTP_XOR_MULT_DOSStub_a3be {
  strings:
    $key_a3be = { f7 d6 [2] 83 ce [2] c4 cc [2] 83 dd [2] cd d1 [2] c1 db [2] d6 d0 [2] cd 9e [2] f0 }

  condition:
    any of them
}