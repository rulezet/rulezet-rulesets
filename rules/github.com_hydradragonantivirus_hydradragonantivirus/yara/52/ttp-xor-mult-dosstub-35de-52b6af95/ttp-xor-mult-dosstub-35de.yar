rule TTP_XOR_MULT_DOSStub_35de {
  strings:
    $key_35de = { 61 b6 [2] 15 ae [2] 52 ac [2] 15 bd [2] 5b b1 [2] 57 bb [2] 40 b0 [2] 5b fe [2] 66 }

  condition:
    any of them
}