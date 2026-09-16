rule TTP_XOR_MULT_DOSStub_b5de {
  strings:
    $key_b5de = { e1 b6 [2] 95 ae [2] d2 ac [2] 95 bd [2] db b1 [2] d7 bb [2] c0 b0 [2] db fe [2] e6 }

  condition:
    any of them
}