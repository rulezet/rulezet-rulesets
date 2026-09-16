rule TTP_XOR_MULT_DOSStub_a517 {
  strings:
    $key_a517 = { f1 7f [2] 85 67 [2] c2 65 [2] 85 74 [2] cb 78 [2] c7 72 [2] d0 79 [2] cb 37 [2] f6 }

  condition:
    any of them
}