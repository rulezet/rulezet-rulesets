rule TTP_XOR_MULT_DOSStub_b587 {
  strings:
    $key_b587 = { e1 ef [2] 95 f7 [2] d2 f5 [2] 95 e4 [2] db e8 [2] d7 e2 [2] c0 e9 [2] db a7 [2] e6 }

  condition:
    any of them
}