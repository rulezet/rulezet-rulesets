rule TTP_XOR_MULT_DOSStub_a564 {
  strings:
    $key_a564 = { f1 0c [2] 85 14 [2] c2 16 [2] 85 07 [2] cb 0b [2] c7 01 [2] d0 0a [2] cb 44 [2] f6 }

  condition:
    any of them
}