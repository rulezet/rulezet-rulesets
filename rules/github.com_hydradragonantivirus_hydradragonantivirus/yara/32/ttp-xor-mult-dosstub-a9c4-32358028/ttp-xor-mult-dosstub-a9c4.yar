rule TTP_XOR_MULT_DOSStub_a9c4 {
  strings:
    $key_a9c4 = { fd ac [2] 89 b4 [2] ce b6 [2] 89 a7 [2] c7 ab [2] cb a1 [2] dc aa [2] c7 e4 [2] fa }

  condition:
    any of them
}