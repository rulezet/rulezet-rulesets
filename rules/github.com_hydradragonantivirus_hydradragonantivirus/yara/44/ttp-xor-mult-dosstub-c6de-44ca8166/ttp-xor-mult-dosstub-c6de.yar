rule TTP_XOR_MULT_DOSStub_c6de {
  strings:
    $key_c6de = { 92 b6 [2] e6 ae [2] a1 ac [2] e6 bd [2] a8 b1 [2] a4 bb [2] b3 b0 [2] a8 fe [2] 95 }

  condition:
    any of them
}