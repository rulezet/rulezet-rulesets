rule TTP_XOR_MULT_DOSStub_43de {
  strings:
    $key_43de = { 17 b6 [2] 63 ae [2] 24 ac [2] 63 bd [2] 2d b1 [2] 21 bb [2] 36 b0 [2] 2d fe [2] 10 }

  condition:
    any of them
}