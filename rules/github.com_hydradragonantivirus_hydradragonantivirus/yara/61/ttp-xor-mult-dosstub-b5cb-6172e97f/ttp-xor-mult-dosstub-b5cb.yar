rule TTP_XOR_MULT_DOSStub_b5cb {
  strings:
    $key_b5cb = { e1 a3 [2] 95 bb [2] d2 b9 [2] 95 a8 [2] db a4 [2] d7 ae [2] c0 a5 [2] db eb [2] e6 }

  condition:
    any of them
}