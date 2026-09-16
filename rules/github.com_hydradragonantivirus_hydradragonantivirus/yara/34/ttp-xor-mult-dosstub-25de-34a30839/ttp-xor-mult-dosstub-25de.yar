rule TTP_XOR_MULT_DOSStub_25de {
  strings:
    $key_25de = { 71 b6 [2] 05 ae [2] 42 ac [2] 05 bd [2] 4b b1 [2] 47 bb [2] 50 b0 [2] 4b fe [2] 76 }

  condition:
    any of them
}