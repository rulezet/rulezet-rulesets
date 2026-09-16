rule TTP_XOR_MULT_DOSStub_a9c6 {
  strings:
    $key_a9c6 = { fd ae [2] 89 b6 [2] ce b4 [2] 89 a5 [2] c7 a9 [2] cb a3 [2] dc a8 [2] c7 e6 [2] fa }

  condition:
    any of them
}