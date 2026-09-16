rule TTP_XOR_MULT_DOSStub_b087 {
  strings:
    $key_b087 = { e4 ef [2] 90 f7 [2] d7 f5 [2] 90 e4 [2] de e8 [2] d2 e2 [2] c5 e9 [2] de a7 [2] e3 }

  condition:
    any of them
}