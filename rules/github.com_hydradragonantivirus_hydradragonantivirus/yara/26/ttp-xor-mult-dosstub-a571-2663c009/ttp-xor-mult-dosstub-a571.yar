rule TTP_XOR_MULT_DOSStub_a571 {
  strings:
    $key_a571 = { f1 19 [2] 85 01 [2] c2 03 [2] 85 12 [2] cb 1e [2] c7 14 [2] d0 1f [2] cb 51 [2] f6 }

  condition:
    any of them
}