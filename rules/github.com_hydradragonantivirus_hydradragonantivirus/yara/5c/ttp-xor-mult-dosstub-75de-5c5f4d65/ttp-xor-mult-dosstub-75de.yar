rule TTP_XOR_MULT_DOSStub_75de {
  strings:
    $key_75de = { 21 b6 [2] 55 ae [2] 12 ac [2] 55 bd [2] 1b b1 [2] 17 bb [2] 00 b0 [2] 1b fe [2] 26 }

  condition:
    any of them
}