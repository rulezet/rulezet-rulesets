rule TTP_XOR_MULT_DOSStub_a9b4 {
  strings:
    $key_a9b4 = { fd dc [2] 89 c4 [2] ce c6 [2] 89 d7 [2] c7 db [2] cb d1 [2] dc da [2] c7 94 [2] fa }

  condition:
    any of them
}