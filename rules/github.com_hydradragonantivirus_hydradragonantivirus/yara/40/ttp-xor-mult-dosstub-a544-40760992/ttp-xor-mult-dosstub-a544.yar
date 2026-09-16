rule TTP_XOR_MULT_DOSStub_a544 {
  strings:
    $key_a544 = { f1 2c [2] 85 34 [2] c2 36 [2] 85 27 [2] cb 2b [2] c7 21 [2] d0 2a [2] cb 64 [2] f6 }

  condition:
    any of them
}