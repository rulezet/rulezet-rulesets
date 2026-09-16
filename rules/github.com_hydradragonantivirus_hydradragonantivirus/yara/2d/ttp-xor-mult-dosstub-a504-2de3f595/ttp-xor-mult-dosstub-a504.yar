rule TTP_XOR_MULT_DOSStub_a504 {
  strings:
    $key_a504 = { f1 6c [2] 85 74 [2] c2 76 [2] 85 67 [2] cb 6b [2] c7 61 [2] d0 6a [2] cb 24 [2] f6 }

  condition:
    any of them
}