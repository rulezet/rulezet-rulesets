rule TTP_XOR_MULT_DOSStub_b4de {
  strings:
    $key_b4de = { e0 b6 [2] 94 ae [2] d3 ac [2] 94 bd [2] da b1 [2] d6 bb [2] c1 b0 [2] da fe [2] e7 }

  condition:
    any of them
}