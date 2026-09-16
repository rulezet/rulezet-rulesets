rule TTP_XOR_MULT_DOSStub_b585 {
  strings:
    $key_b585 = { e1 ed [2] 95 f5 [2] d2 f7 [2] 95 e6 [2] db ea [2] d7 e0 [2] c0 eb [2] db a5 [2] e6 }

  condition:
    any of them
}