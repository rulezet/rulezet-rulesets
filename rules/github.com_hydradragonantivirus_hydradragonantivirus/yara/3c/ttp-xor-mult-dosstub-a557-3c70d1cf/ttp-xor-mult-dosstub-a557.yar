rule TTP_XOR_MULT_DOSStub_a557 {
  strings:
    $key_a557 = { f1 3f [2] 85 27 [2] c2 25 [2] 85 34 [2] cb 38 [2] c7 32 [2] d0 39 [2] cb 77 [2] f6 }

  condition:
    any of them
}