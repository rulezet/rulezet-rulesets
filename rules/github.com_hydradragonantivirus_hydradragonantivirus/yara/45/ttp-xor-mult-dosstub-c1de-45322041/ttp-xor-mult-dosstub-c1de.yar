rule TTP_XOR_MULT_DOSStub_c1de {
  strings:
    $key_c1de = { 95 b6 [2] e1 ae [2] a6 ac [2] e1 bd [2] af b1 [2] a3 bb [2] b4 b0 [2] af fe [2] 92 }

  condition:
    any of them
}