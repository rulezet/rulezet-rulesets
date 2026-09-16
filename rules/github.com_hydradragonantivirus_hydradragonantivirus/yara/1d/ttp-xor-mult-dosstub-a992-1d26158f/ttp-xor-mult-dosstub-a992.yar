rule TTP_XOR_MULT_DOSStub_a992 {
  strings:
    $key_a992 = { fd fa [2] 89 e2 [2] ce e0 [2] 89 f1 [2] c7 fd [2] cb f7 [2] dc fc [2] c7 b2 [2] fa }

  condition:
    any of them
}