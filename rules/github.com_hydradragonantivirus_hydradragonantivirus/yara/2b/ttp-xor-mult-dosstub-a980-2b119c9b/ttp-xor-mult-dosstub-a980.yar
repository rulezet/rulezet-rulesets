rule TTP_XOR_MULT_DOSStub_a980 {
  strings:
    $key_a980 = { fd e8 [2] 89 f0 [2] ce f2 [2] 89 e3 [2] c7 ef [2] cb e5 [2] dc ee [2] c7 a0 [2] fa }

  condition:
    any of them
}