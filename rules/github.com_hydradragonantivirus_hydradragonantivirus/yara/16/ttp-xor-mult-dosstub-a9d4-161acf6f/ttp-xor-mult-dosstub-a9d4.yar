rule TTP_XOR_MULT_DOSStub_a9d4 {
  strings:
    $key_a9d4 = { fd bc [2] 89 a4 [2] ce a6 [2] 89 b7 [2] c7 bb [2] cb b1 [2] dc ba [2] c7 f4 [2] fa }

  condition:
    any of them
}