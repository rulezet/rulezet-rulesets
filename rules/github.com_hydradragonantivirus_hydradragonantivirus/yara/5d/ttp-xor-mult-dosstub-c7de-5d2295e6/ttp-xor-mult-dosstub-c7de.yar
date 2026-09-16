rule TTP_XOR_MULT_DOSStub_c7de {
  strings:
    $key_c7de = { 93 b6 [2] e7 ae [2] a0 ac [2] e7 bd [2] a9 b1 [2] a5 bb [2] b2 b0 [2] a9 fe [2] 94 }

  condition:
    any of them
}