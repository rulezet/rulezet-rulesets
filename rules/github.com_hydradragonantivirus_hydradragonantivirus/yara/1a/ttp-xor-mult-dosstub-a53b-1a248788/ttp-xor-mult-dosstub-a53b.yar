rule TTP_XOR_MULT_DOSStub_a53b {
  strings:
    $key_a53b = { f1 53 [2] 85 4b [2] c2 49 [2] 85 58 [2] cb 54 [2] c7 5e [2] d0 55 [2] cb 1b [2] f6 }

  condition:
    any of them
}