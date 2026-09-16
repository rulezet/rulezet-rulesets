rule TTP_XOR_MULT_DOSStub_a990 {
  strings:
    $key_a990 = { fd f8 [2] 89 e0 [2] ce e2 [2] 89 f3 [2] c7 ff [2] cb f5 [2] dc fe [2] c7 b0 [2] fa }

  condition:
    any of them
}