rule TTP_XOR_MULT_DOSStub_a5e9 {
  strings:
    $key_a5e9 = { f1 81 [2] 85 99 [2] c2 9b [2] 85 8a [2] cb 86 [2] c7 8c [2] d0 87 [2] cb c9 [2] f6 }

  condition:
    any of them
}