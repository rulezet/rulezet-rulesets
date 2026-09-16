rule TTP_XOR_MULT_DOSStub_20de {
  strings:
    $key_20de = { 74 b6 [2] 00 ae [2] 47 ac [2] 00 bd [2] 4e b1 [2] 42 bb [2] 55 b0 [2] 4e fe [2] 73 }

  condition:
    any of them
}