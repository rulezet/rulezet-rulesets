rule TTP_XOR_MULT_DOSStub_a556 {
  strings:
    $key_a556 = { f1 3e [2] 85 26 [2] c2 24 [2] 85 35 [2] cb 39 [2] c7 33 [2] d0 38 [2] cb 76 [2] f6 }

  condition:
    any of them
}