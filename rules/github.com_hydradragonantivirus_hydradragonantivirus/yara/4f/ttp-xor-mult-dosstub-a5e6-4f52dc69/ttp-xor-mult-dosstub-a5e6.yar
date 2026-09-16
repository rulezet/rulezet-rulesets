rule TTP_XOR_MULT_DOSStub_a5e6 {
  strings:
    $key_a5e6 = { f1 8e [2] 85 96 [2] c2 94 [2] 85 85 [2] cb 89 [2] c7 83 [2] d0 88 [2] cb c6 [2] f6 }

  condition:
    any of them
}