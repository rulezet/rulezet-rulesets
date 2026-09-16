rule TTP_XOR_MULT_DOSStub_a531 {
  strings:
    $key_a531 = { f1 59 [2] 85 41 [2] c2 43 [2] 85 52 [2] cb 5e [2] c7 54 [2] d0 5f [2] cb 11 [2] f6 }

  condition:
    any of them
}