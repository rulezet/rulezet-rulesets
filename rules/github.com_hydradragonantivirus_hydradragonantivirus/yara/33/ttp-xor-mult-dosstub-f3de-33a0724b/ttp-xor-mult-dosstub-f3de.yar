rule TTP_XOR_MULT_DOSStub_f3de {
  strings:
    $key_f3de = { a7 b6 [2] d3 ae [2] 94 ac [2] d3 bd [2] 9d b1 [2] 91 bb [2] 86 b0 [2] 9d fe [2] a0 }

  condition:
    any of them
}