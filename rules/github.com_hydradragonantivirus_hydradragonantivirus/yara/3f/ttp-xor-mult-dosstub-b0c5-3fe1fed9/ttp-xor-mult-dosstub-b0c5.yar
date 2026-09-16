rule TTP_XOR_MULT_DOSStub_b0c5 {
  strings:
    $key_b0c5 = { e4 ad [2] 90 b5 [2] d7 b7 [2] 90 a6 [2] de aa [2] d2 a0 [2] c5 ab [2] de e5 [2] e3 }

  condition:
    any of them
}