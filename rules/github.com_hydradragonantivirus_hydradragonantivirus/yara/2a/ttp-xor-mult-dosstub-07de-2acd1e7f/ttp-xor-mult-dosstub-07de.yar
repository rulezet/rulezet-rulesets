rule TTP_XOR_MULT_DOSStub_07de {
  strings:
    $key_07de = { 53 b6 [2] 27 ae [2] 60 ac [2] 27 bd [2] 69 b1 [2] 65 bb [2] 72 b0 [2] 69 fe [2] 54 }

  condition:
    any of them
}