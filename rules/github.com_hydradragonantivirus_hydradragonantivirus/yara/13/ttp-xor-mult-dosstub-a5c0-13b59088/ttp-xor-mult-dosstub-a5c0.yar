rule TTP_XOR_MULT_DOSStub_a5c0 {
  strings:
    $key_a5c0 = { f1 a8 [2] 85 b0 [2] c2 b2 [2] 85 a3 [2] cb af [2] c7 a5 [2] d0 ae [2] cb e0 [2] f6 }

  condition:
    any of them
}