rule TTP_XOR_MULT_DOSStub_a9d1 {
  strings:
    $key_a9d1 = { fd b9 [2] 89 a1 [2] ce a3 [2] 89 b2 [2] c7 be [2] cb b4 [2] dc bf [2] c7 f1 [2] fa }

  condition:
    any of them
}