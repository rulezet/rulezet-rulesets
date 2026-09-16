rule TTP_XOR_MULT_DOSStub_b583 {
  strings:
    $key_b583 = { e1 eb [2] 95 f3 [2] d2 f1 [2] 95 e0 [2] db ec [2] d7 e6 [2] c0 ed [2] db a3 [2] e6 }

  condition:
    any of them
}