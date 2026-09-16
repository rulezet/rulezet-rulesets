rule TTP_XOR_MULT_DOSStub_04de {
  strings:
    $key_04de = { 50 b6 [2] 24 ae [2] 63 ac [2] 24 bd [2] 6a b1 [2] 66 bb [2] 71 b0 [2] 6a fe [2] 57 }

  condition:
    any of them
}