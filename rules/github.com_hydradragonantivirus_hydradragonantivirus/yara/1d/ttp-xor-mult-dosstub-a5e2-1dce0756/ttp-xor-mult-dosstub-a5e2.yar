rule TTP_XOR_MULT_DOSStub_a5e2 {
  strings:
    $key_a5e2 = { f1 8a [2] 85 92 [2] c2 90 [2] 85 81 [2] cb 8d [2] c7 87 [2] d0 8c [2] cb c2 [2] f6 }

  condition:
    any of them
}