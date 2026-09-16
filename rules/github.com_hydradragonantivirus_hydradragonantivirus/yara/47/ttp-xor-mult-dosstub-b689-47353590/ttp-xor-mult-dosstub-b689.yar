rule TTP_XOR_MULT_DOSStub_b689 {
  strings:
    $key_b689 = { e2 e1 [2] 96 f9 [2] d1 fb [2] 96 ea [2] d8 e6 [2] d4 ec [2] c3 e7 [2] d8 a9 [2] e5 }

  condition:
    any of them
}