rule TTP_XOR_MULT_DOSStub_a500 {
  strings:
    $key_a500 = { f1 68 [2] 85 70 [2] c2 72 [2] 85 63 [2] cb 6f [2] c7 65 [2] d0 6e [2] cb 20 [2] f6 }

  condition:
    any of them
}