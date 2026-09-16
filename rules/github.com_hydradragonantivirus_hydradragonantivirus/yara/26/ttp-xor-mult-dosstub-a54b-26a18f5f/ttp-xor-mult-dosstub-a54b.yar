rule TTP_XOR_MULT_DOSStub_a54b {
  strings:
    $key_a54b = { f1 23 [2] 85 3b [2] c2 39 [2] 85 28 [2] cb 24 [2] c7 2e [2] d0 25 [2] cb 6b [2] f6 }

  condition:
    any of them
}