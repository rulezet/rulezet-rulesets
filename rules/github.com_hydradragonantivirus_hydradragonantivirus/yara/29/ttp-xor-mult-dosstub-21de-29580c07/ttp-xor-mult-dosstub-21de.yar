rule TTP_XOR_MULT_DOSStub_21de {
  strings:
    $key_21de = { 75 b6 [2] 01 ae [2] 46 ac [2] 01 bd [2] 4f b1 [2] 43 bb [2] 54 b0 [2] 4f fe [2] 72 }

  condition:
    any of them
}