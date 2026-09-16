rule TTP_XOR_MULT_DOSStub_10de {
  strings:
    $key_10de = { 44 b6 [2] 30 ae [2] 77 ac [2] 30 bd [2] 7e b1 [2] 72 bb [2] 65 b0 [2] 7e fe [2] 43 }

  condition:
    any of them
}