rule TTP_XOR_MULT_DOSStub_a5f5 {
  strings:
    $key_a5f5 = { f1 9d [2] 85 85 [2] c2 87 [2] 85 96 [2] cb 9a [2] c7 90 [2] d0 9b [2] cb d5 [2] f6 }

  condition:
    any of them
}