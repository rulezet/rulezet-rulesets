rule TTP_XOR_MULT_DOSStub_a5c5 {
  strings:
    $key_a5c5 = { f1 ad [2] 85 b5 [2] c2 b7 [2] 85 a6 [2] cb aa [2] c7 a0 [2] d0 ab [2] cb e5 [2] f6 }

  condition:
    any of them
}