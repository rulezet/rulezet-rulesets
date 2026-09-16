rule TTP_XOR_MULT_DOSStub_b08b {
  strings:
    $key_b08b = { e4 e3 [2] 90 fb [2] d7 f9 [2] 90 e8 [2] de e4 [2] d2 ee [2] c5 e5 [2] de ab [2] e3 }

  condition:
    any of them
}