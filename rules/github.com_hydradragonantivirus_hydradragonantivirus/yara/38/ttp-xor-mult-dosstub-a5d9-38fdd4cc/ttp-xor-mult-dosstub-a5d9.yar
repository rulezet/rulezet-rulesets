rule TTP_XOR_MULT_DOSStub_a5d9 {
  strings:
    $key_a5d9 = { f1 b1 [2] 85 a9 [2] c2 ab [2] 85 ba [2] cb b6 [2] c7 bc [2] d0 b7 [2] cb f9 [2] f6 }

  condition:
    any of them
}