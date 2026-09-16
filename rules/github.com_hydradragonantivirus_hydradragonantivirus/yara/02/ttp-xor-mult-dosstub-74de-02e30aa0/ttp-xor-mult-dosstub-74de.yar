rule TTP_XOR_MULT_DOSStub_74de {
  strings:
    $key_74de = { 20 b6 [2] 54 ae [2] 13 ac [2] 54 bd [2] 1a b1 [2] 16 bb [2] 01 b0 [2] 1a fe [2] 27 }

  condition:
    any of them
}