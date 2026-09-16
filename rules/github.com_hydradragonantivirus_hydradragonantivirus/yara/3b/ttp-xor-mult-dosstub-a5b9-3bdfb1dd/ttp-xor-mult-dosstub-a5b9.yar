rule TTP_XOR_MULT_DOSStub_a5b9 {
  strings:
    $key_a5b9 = { f1 d1 [2] 85 c9 [2] c2 cb [2] 85 da [2] cb d6 [2] c7 dc [2] d0 d7 [2] cb 99 [2] f6 }

  condition:
    any of them
}