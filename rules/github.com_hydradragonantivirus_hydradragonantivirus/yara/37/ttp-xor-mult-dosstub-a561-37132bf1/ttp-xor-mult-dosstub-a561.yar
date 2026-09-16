rule TTP_XOR_MULT_DOSStub_a561 {
  strings:
    $key_a561 = { f1 09 [2] 85 11 [2] c2 13 [2] 85 02 [2] cb 0e [2] c7 04 [2] d0 0f [2] cb 41 [2] f6 }

  condition:
    any of them
}