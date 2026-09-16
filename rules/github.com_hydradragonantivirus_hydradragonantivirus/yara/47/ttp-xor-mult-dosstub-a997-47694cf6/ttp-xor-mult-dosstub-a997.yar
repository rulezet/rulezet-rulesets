rule TTP_XOR_MULT_DOSStub_a997 {
  strings:
    $key_a997 = { fd ff [2] 89 e7 [2] ce e5 [2] 89 f4 [2] c7 f8 [2] cb f2 [2] dc f9 [2] c7 b7 [2] fa }

  condition:
    any of them
}