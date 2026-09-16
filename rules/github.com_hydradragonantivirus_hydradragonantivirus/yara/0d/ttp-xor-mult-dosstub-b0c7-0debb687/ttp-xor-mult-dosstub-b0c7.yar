rule TTP_XOR_MULT_DOSStub_b0c7 {
  strings:
    $key_b0c7 = { e4 af [2] 90 b7 [2] d7 b5 [2] 90 a4 [2] de a8 [2] d2 a2 [2] c5 a9 [2] de e7 [2] e3 }

  condition:
    any of them
}