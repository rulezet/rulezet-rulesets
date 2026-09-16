rule TTP_XOR_MULT_DOSStub_a986 {
  strings:
    $key_a986 = { fd ee [2] 89 f6 [2] ce f4 [2] 89 e5 [2] c7 e9 [2] cb e3 [2] dc e8 [2] c7 a6 [2] fa }

  condition:
    any of them
}