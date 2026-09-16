rule TTP_XOR_MULT_DOSStub_b389 {
  strings:
    $key_b389 = { e7 e1 [2] 93 f9 [2] d4 fb [2] 93 ea [2] dd e6 [2] d1 ec [2] c6 e7 [2] dd a9 [2] e0 }

  condition:
    any of them
}