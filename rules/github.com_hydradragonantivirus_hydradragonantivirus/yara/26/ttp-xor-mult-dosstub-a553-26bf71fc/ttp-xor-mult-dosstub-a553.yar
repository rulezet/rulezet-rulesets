rule TTP_XOR_MULT_DOSStub_a553 {
  strings:
    $key_a553 = { f1 3b [2] 85 23 [2] c2 21 [2] 85 30 [2] cb 3c [2] c7 36 [2] d0 3d [2] cb 73 [2] f6 }

  condition:
    any of them
}