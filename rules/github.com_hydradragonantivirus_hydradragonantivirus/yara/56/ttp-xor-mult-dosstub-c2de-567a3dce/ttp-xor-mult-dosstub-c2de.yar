rule TTP_XOR_MULT_DOSStub_c2de {
  strings:
    $key_c2de = { 96 b6 [2] e2 ae [2] a5 ac [2] e2 bd [2] ac b1 [2] a0 bb [2] b7 b0 [2] ac fe [2] 91 }

  condition:
    any of them
}