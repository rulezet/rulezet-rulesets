rule TTP_XOR_MULT_DOSStub_36de {
  strings:
    $key_36de = { 62 b6 [2] 16 ae [2] 51 ac [2] 16 bd [2] 58 b1 [2] 54 bb [2] 43 b0 [2] 58 fe [2] 65 }

  condition:
    any of them
}