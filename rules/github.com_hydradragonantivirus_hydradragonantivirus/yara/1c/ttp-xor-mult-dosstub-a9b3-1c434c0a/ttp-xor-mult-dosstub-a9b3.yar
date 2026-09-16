rule TTP_XOR_MULT_DOSStub_a9b3 {
  strings:
    $key_a9b3 = { fd db [2] 89 c3 [2] ce c1 [2] 89 d0 [2] c7 dc [2] cb d6 [2] dc dd [2] c7 93 [2] fa }

  condition:
    any of them
}