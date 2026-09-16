rule TTP_XOR_MULT_DOSStub_a9c0 {
  strings:
    $key_a9c0 = { fd a8 [2] 89 b0 [2] ce b2 [2] 89 a3 [2] c7 af [2] cb a5 [2] dc ae [2] c7 e0 [2] fa }

  condition:
    any of them
}