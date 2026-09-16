rule TTP_XOR_MULT_DOSStub_a5be {
  strings:
    $key_a5be = { f1 d6 [2] 85 ce [2] c2 cc [2] 85 dd [2] cb d1 [2] c7 db [2] d0 d0 [2] cb 9e [2] f6 }

  condition:
    any of them
}