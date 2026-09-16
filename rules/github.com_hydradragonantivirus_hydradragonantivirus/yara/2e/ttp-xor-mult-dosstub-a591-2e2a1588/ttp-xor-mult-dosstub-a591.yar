rule TTP_XOR_MULT_DOSStub_a591 {
  strings:
    $key_a591 = { f1 f9 [2] 85 e1 [2] c2 e3 [2] 85 f2 [2] cb fe [2] c7 f4 [2] d0 ff [2] cb b1 [2] f6 }

  condition:
    any of them
}