rule TTP_XOR_MULT_DOSStub_b0c6 {
  strings:
    $key_b0c6 = { e4 ae [2] 90 b6 [2] d7 b4 [2] 90 a5 [2] de a9 [2] d2 a3 [2] c5 a8 [2] de e6 [2] e3 }

  condition:
    any of them
}