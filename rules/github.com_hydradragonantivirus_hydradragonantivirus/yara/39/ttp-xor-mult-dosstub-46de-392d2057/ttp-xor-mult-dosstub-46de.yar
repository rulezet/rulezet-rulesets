rule TTP_XOR_MULT_DOSStub_46de {
  strings:
    $key_46de = { 12 b6 [2] 66 ae [2] 21 ac [2] 66 bd [2] 28 b1 [2] 24 bb [2] 33 b0 [2] 28 fe [2] 15 }

  condition:
    any of them
}