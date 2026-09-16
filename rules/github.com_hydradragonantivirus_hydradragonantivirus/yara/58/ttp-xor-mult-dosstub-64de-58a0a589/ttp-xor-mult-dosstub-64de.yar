rule TTP_XOR_MULT_DOSStub_64de {
  strings:
    $key_64de = { 30 b6 [2] 44 ae [2] 03 ac [2] 44 bd [2] 0a b1 [2] 06 bb [2] 11 b0 [2] 0a fe [2] 37 }

  condition:
    any of them
}