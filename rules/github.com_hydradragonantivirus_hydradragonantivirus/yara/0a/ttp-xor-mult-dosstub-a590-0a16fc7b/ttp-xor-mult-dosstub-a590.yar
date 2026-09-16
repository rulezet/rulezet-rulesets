rule TTP_XOR_MULT_DOSStub_a590 {
  strings:
    $key_a590 = { f1 f8 [2] 85 e0 [2] c2 e2 [2] 85 f3 [2] cb ff [2] c7 f5 [2] d0 fe [2] cb b0 [2] f6 }

  condition:
    any of them
}