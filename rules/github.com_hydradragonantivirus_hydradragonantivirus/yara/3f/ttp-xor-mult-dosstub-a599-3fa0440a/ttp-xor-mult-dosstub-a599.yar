rule TTP_XOR_MULT_DOSStub_a599 {
  strings:
    $key_a599 = { f1 f1 [2] 85 e9 [2] c2 eb [2] 85 fa [2] cb f6 [2] c7 fc [2] d0 f7 [2] cb b9 [2] f6 }

  condition:
    any of them
}