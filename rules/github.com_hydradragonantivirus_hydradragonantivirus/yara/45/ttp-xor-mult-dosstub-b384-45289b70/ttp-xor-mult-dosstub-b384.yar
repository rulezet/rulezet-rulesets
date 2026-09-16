rule TTP_XOR_MULT_DOSStub_b384 {
  strings:
    $key_b384 = { e7 ec [2] 93 f4 [2] d4 f6 [2] 93 e7 [2] dd eb [2] d1 e1 [2] c6 ea [2] dd a4 [2] e0 }

  condition:
    any of them
}