rule TTP_XOR_MULT_DOSStub_a532 {
  strings:
    $key_a532 = { f1 5a [2] 85 42 [2] c2 40 [2] 85 51 [2] cb 5d [2] c7 57 [2] d0 5c [2] cb 12 [2] f6 }

  condition:
    any of them
}