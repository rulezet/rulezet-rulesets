rule TTP_XOR_MULT_DOSStub_a520 {
  strings:
    $key_a520 = { f1 48 [2] 85 50 [2] c2 52 [2] 85 43 [2] cb 4f [2] c7 45 [2] d0 4e [2] cb 00 [2] f6 }

  condition:
    any of them
}