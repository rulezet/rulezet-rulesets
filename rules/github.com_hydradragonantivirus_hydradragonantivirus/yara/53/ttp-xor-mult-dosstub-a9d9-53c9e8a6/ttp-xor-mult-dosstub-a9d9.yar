rule TTP_XOR_MULT_DOSStub_a9d9 {
  strings:
    $key_a9d9 = { fd b1 [2] 89 a9 [2] ce ab [2] 89 ba [2] c7 b6 [2] cb bc [2] dc b7 [2] c7 f9 [2] fa }

  condition:
    any of them
}