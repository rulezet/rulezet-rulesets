rule TTP_XOR_MULT_DOSStub_cec9 {
  strings:
    $key_cec9 = { 9a a1 [2] ee b9 [2] a9 bb [2] ee aa [2] a0 a6 [2] ac ac [2] bb a7 [2] a0 e9 [2] 9d }

  condition:
    any of them
}