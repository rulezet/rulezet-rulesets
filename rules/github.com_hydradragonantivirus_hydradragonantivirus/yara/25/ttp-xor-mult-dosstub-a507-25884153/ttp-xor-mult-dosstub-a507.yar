rule TTP_XOR_MULT_DOSStub_a507 {
  strings:
    $key_a507 = { f1 6f [2] 85 77 [2] c2 75 [2] 85 64 [2] cb 68 [2] c7 62 [2] d0 69 [2] cb 27 [2] f6 }

  condition:
    any of them
}