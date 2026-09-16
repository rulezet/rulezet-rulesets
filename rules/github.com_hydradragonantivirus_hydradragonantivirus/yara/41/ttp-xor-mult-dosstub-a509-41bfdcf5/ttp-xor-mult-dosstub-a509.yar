rule TTP_XOR_MULT_DOSStub_a509 {
  strings:
    $key_a509 = { f1 61 [2] 85 79 [2] c2 7b [2] 85 6a [2] cb 66 [2] c7 6c [2] d0 67 [2] cb 29 [2] f6 }

  condition:
    any of them
}