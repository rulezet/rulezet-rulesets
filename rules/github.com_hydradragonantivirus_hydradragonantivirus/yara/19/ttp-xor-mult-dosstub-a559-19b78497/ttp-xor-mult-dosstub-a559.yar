rule TTP_XOR_MULT_DOSStub_a559 {
  strings:
    $key_a559 = { f1 31 [2] 85 29 [2] c2 2b [2] 85 3a [2] cb 36 [2] c7 3c [2] d0 37 [2] cb 79 [2] f6 }

  condition:
    any of them
}