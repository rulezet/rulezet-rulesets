rule TTP_XOR_MULT_DOSStub_eb98 {
  strings:
    $key_eb98 = { bf f0 [2] cb e8 [2] 8c ea [2] cb fb [2] 85 f7 [2] 89 fd [2] 9e f6 [2] 85 b8 [2] b8 }

  condition:
    any of them
}