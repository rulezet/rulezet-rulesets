rule TTP_XOR_MULT_DOSStub_45de {
  strings:
    $key_45de = { 11 b6 [2] 65 ae [2] 22 ac [2] 65 bd [2] 2b b1 [2] 27 bb [2] 30 b0 [2] 2b fe [2] 16 }

  condition:
    any of them
}