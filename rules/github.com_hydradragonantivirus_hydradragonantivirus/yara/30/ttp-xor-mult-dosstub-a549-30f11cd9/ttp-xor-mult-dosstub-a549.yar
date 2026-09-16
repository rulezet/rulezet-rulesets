rule TTP_XOR_MULT_DOSStub_a549 {
  strings:
    $key_a549 = { f1 21 [2] 85 39 [2] c2 3b [2] 85 2a [2] cb 26 [2] c7 2c [2] d0 27 [2] cb 69 [2] f6 }

  condition:
    any of them
}