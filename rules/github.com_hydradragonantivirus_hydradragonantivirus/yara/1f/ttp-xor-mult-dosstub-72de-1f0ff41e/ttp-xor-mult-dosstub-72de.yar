rule TTP_XOR_MULT_DOSStub_72de {
  strings:
    $key_72de = { 26 b6 [2] 52 ae [2] 15 ac [2] 52 bd [2] 1c b1 [2] 10 bb [2] 07 b0 [2] 1c fe [2] 21 }

  condition:
    any of them
}