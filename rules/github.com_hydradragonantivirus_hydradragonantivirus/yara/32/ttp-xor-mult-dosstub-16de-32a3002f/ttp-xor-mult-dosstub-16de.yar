rule TTP_XOR_MULT_DOSStub_16de {
  strings:
    $key_16de = { 42 b6 [2] 36 ae [2] 71 ac [2] 36 bd [2] 78 b1 [2] 74 bb [2] 63 b0 [2] 78 fe [2] 45 }

  condition:
    any of them
}