rule TTP_XOR_MULT_DOSStub_a597 {
  strings:
    $key_a597 = { f1 ff [2] 85 e7 [2] c2 e5 [2] 85 f4 [2] cb f8 [2] c7 f2 [2] d0 f9 [2] cb b7 [2] f6 }

  condition:
    any of them
}