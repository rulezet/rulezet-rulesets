rule TTP_XOR_MULT_DOSStub_a5f1 {
  strings:
    $key_a5f1 = { f1 99 [2] 85 81 [2] c2 83 [2] 85 92 [2] cb 9e [2] c7 94 [2] d0 9f [2] cb d1 [2] f6 }

  condition:
    any of them
}