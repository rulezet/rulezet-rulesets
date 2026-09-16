rule TTP_XOR_MULT_DOSStub_b693 {
  strings:
    $key_b693 = { e2 fb [2] 96 e3 [2] d1 e1 [2] 96 f0 [2] d8 fc [2] d4 f6 [2] c3 fd [2] d8 b3 [2] e5 }

  condition:
    any of them
}