rule TTP_XOR_MULT_DOSStub_50de {
  strings:
    $key_50de = { 04 b6 [2] 70 ae [2] 37 ac [2] 70 bd [2] 3e b1 [2] 32 bb [2] 25 b0 [2] 3e fe [2] 03 }

  condition:
    any of them
}