rule TTP_XOR_MULT_DOSStub_01de {
  strings:
    $key_01de = { 55 b6 [2] 21 ae [2] 66 ac [2] 21 bd [2] 6f b1 [2] 63 bb [2] 74 b0 [2] 6f fe [2] 52 }

  condition:
    any of them
}