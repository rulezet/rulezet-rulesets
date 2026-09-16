rule TTP_XOR_MULT_DOSStub_b086 {
  strings:
    $key_b086 = { e4 ee [2] 90 f6 [2] d7 f4 [2] 90 e5 [2] de e9 [2] d2 e3 [2] c5 e8 [2] de a6 [2] e3 }

  condition:
    any of them
}