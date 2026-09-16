rule TTP_XOR_MULT_DOSStub_a547 {
  strings:
    $key_a547 = { f1 2f [2] 85 37 [2] c2 35 [2] 85 24 [2] cb 28 [2] c7 22 [2] d0 29 [2] cb 67 [2] f6 }

  condition:
    any of them
}