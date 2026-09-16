rule TTP_XOR_MULT_DOSStub_a530 {
  strings:
    $key_a530 = { f1 58 [2] 85 40 [2] c2 42 [2] 85 53 [2] cb 5f [2] c7 55 [2] d0 5e [2] cb 10 [2] f6 }

  condition:
    any of them
}