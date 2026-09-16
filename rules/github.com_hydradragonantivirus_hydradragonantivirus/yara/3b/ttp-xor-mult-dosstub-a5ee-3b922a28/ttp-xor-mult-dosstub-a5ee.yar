rule TTP_XOR_MULT_DOSStub_a5ee {
  strings:
    $key_a5ee = { f1 86 [2] 85 9e [2] c2 9c [2] 85 8d [2] cb 81 [2] c7 8b [2] d0 80 [2] cb ce [2] f6 }

  condition:
    any of them
}