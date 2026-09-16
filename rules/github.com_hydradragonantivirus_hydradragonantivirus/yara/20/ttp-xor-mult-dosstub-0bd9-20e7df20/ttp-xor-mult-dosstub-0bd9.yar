rule TTP_XOR_MULT_DOSStub_0bd9 {
  strings:
    $key_0bd9 = { 5f b1 [2] 2b a9 [2] 6c ab [2] 2b ba [2] 65 b6 [2] 69 bc [2] 7e b7 [2] 65 f9 [2] 58 }

  condition:
    any of them
}