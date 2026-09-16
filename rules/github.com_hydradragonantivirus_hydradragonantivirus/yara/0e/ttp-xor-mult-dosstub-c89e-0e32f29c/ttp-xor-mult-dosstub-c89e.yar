rule TTP_XOR_MULT_DOSStub_c89e {
  strings:
    $key_c89e = { 9c f6 [2] e8 ee [2] af ec [2] e8 fd [2] a6 f1 [2] aa fb [2] bd f0 [2] a6 be [2] 9b }

  condition:
    any of them
}