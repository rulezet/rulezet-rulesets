rule TTP_XOR_MULT_DOSStub_42de {
  strings:
    $key_42de = { 16 b6 [2] 62 ae [2] 25 ac [2] 62 bd [2] 2c b1 [2] 20 bb [2] 37 b0 [2] 2c fe [2] 11 }

  condition:
    any of them
}