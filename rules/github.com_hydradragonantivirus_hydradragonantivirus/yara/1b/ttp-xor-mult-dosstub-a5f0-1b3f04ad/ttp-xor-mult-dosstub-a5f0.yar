rule TTP_XOR_MULT_DOSStub_a5f0 {
  strings:
    $key_a5f0 = { f1 98 [2] 85 80 [2] c2 82 [2] 85 93 [2] cb 9f [2] c7 95 [2] d0 9e [2] cb d0 [2] f6 }

  condition:
    any of them
}