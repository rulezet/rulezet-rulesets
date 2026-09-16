rule TTP_XOR_MULT_DOSStub_b584 {
  strings:
    $key_b584 = { e1 ec [2] 95 f4 [2] d2 f6 [2] 95 e7 [2] db eb [2] d7 e1 [2] c0 ea [2] db a4 [2] e6 }

  condition:
    any of them
}