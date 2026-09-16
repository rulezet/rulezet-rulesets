rule TTP_XOR_MULT_DOSStub_a515 {
  strings:
    $key_a515 = { f1 7d [2] 85 65 [2] c2 67 [2] 85 76 [2] cb 7a [2] c7 70 [2] d0 7b [2] cb 35 [2] f6 }

  condition:
    any of them
}