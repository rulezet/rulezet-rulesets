rule TTP_XOR_MULT_DOSStub_a5e4 {
  strings:
    $key_a5e4 = { f1 8c [2] 85 94 [2] c2 96 [2] 85 87 [2] cb 8b [2] c7 81 [2] d0 8a [2] cb c4 [2] f6 }

  condition:
    any of them
}