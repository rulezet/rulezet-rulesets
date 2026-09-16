rule TTP_XOR_MULT_DOSStub_a528 {
  strings:
    $key_a528 = { f1 40 [2] 85 58 [2] c2 5a [2] 85 4b [2] cb 47 [2] c7 4d [2] d0 46 [2] cb 08 [2] f6 }

  condition:
    any of them
}