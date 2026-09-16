rule TTP_XOR_MULT_DOSStub_a9d5 {
  strings:
    $key_a9d5 = { fd bd [2] 89 a5 [2] ce a7 [2] 89 b6 [2] c7 ba [2] cb b0 [2] dc bb [2] c7 f5 [2] fa }

  condition:
    any of them
}