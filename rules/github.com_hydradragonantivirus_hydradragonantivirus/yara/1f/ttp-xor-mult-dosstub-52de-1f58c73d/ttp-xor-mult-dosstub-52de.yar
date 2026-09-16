rule TTP_XOR_MULT_DOSStub_52de {
  strings:
    $key_52de = { 06 b6 [2] 72 ae [2] 35 ac [2] 72 bd [2] 3c b1 [2] 30 bb [2] 27 b0 [2] 3c fe [2] 01 }

  condition:
    any of them
}