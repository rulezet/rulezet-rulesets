rule TTP_XOR_MULT_DOSStub_a982 {
  strings:
    $key_a982 = { fd ea [2] 89 f2 [2] ce f0 [2] 89 e1 [2] c7 ed [2] cb e7 [2] dc ec [2] c7 a2 [2] fa }

  condition:
    any of them
}