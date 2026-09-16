rule TTP_XOR_MULT_DOSStub_a524 {
  strings:
    $key_a524 = { f1 4c [2] 85 54 [2] c2 56 [2] 85 47 [2] cb 4b [2] c7 41 [2] d0 4a [2] cb 04 [2] f6 }

  condition:
    any of them
}