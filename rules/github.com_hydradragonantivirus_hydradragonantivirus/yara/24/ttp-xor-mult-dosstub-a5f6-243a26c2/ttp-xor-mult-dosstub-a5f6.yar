rule TTP_XOR_MULT_DOSStub_a5f6 {
  strings:
    $key_a5f6 = { f1 9e [2] 85 86 [2] c2 84 [2] 85 95 [2] cb 99 [2] c7 93 [2] d0 98 [2] cb d6 [2] f6 }

  condition:
    any of them
}