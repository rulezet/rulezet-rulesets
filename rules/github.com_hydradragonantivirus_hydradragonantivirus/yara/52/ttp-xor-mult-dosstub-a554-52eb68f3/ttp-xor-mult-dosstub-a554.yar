rule TTP_XOR_MULT_DOSStub_a554 {
  strings:
    $key_a554 = { f1 3c [2] 85 24 [2] c2 26 [2] 85 37 [2] cb 3b [2] c7 31 [2] d0 3a [2] cb 74 [2] f6 }

  condition:
    any of them
}