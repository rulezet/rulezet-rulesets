rule TTP_XOR_MULT_DOSStub_a59a {
  strings:
    $key_a59a = { f1 f2 [2] 85 ea [2] c2 e8 [2] 85 f9 [2] cb f5 [2] c7 ff [2] d0 f4 [2] cb ba [2] f6 }

  condition:
    any of them
}