rule TTP_XOR_MULT_DOSStub_a505 {
  strings:
    $key_a505 = { f1 6d [2] 85 75 [2] c2 77 [2] 85 66 [2] cb 6a [2] c7 60 [2] d0 6b [2] cb 25 [2] f6 }

  condition:
    any of them
}