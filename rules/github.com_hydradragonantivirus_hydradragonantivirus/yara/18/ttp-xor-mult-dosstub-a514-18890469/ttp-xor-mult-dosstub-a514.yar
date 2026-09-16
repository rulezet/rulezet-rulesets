rule TTP_XOR_MULT_DOSStub_a514 {
  strings:
    $key_a514 = { f1 7c [2] 85 64 [2] c2 66 [2] 85 77 [2] cb 7b [2] c7 71 [2] d0 7a [2] cb 34 [2] f6 }

  condition:
    any of them
}