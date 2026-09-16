rule TTP_XOR_MULT_DOSStub_b793 {
  strings:
    $key_b793 = { e3 fb [2] 97 e3 [2] d0 e1 [2] 97 f0 [2] d9 fc [2] d5 f6 [2] c2 fd [2] d9 b3 [2] e4 }

  condition:
    any of them
}