rule TTP_XOR_MULT_DOSStub_b089 {
  strings:
    $key_b089 = { e4 e1 [2] 90 f9 [2] d7 fb [2] 90 ea [2] de e6 [2] d2 ec [2] c5 e7 [2] de a9 [2] e3 }

  condition:
    any of them
}