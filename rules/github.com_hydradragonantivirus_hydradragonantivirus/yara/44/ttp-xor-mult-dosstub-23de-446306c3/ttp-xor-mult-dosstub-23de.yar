rule TTP_XOR_MULT_DOSStub_23de {
  strings:
    $key_23de = { 77 b6 [2] 03 ae [2] 44 ac [2] 03 bd [2] 4d b1 [2] 41 bb [2] 56 b0 [2] 4d fe [2] 70 }

  condition:
    any of them
}