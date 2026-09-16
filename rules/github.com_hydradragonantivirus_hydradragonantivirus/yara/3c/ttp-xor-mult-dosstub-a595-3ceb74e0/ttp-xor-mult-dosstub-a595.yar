rule TTP_XOR_MULT_DOSStub_a595 {
  strings:
    $key_a595 = { f1 fd [2] 85 e5 [2] c2 e7 [2] 85 f6 [2] cb fa [2] c7 f0 [2] d0 fb [2] cb b5 [2] f6 }

  condition:
    any of them
}