rule TTP_XOR_MULT_DOSStub_b593 {
  strings:
    $key_b593 = { e1 fb [2] 95 e3 [2] d2 e1 [2] 95 f0 [2] db fc [2] d7 f6 [2] c0 fd [2] db b3 [2] e6 }

  condition:
    any of them
}