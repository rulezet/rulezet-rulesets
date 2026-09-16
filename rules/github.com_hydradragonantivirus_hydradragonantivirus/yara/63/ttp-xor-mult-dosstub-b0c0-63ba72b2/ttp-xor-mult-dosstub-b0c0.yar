rule TTP_XOR_MULT_DOSStub_b0c0 {
  strings:
    $key_b0c0 = { e4 a8 [2] 90 b0 [2] d7 b2 [2] 90 a3 [2] de af [2] d2 a5 [2] c5 ae [2] de e0 [2] e3 }

  condition:
    any of them
}