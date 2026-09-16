rule TTP_XOR_MULT_DOSStub_a5f3 {
  strings:
    $key_a5f3 = { f1 9b [2] 85 83 [2] c2 81 [2] 85 90 [2] cb 9c [2] c7 96 [2] d0 9d [2] cb d3 [2] f6 }

  condition:
    any of them
}