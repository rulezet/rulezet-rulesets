rule TTP_XOR_MULT_DOSStub_54de {
  strings:
    $key_54de = { 00 b6 [2] 74 ae [2] 33 ac [2] 74 bd [2] 3a b1 [2] 36 bb [2] 21 b0 [2] 3a fe [2] 07 }

  condition:
    any of them
}