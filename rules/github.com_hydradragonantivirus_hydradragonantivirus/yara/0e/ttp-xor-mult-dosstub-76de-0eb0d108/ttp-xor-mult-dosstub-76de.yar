rule TTP_XOR_MULT_DOSStub_76de {
  strings:
    $key_76de = { 22 b6 [2] 56 ae [2] 11 ac [2] 56 bd [2] 18 b1 [2] 14 bb [2] 03 b0 [2] 18 fe [2] 25 }

  condition:
    any of them
}