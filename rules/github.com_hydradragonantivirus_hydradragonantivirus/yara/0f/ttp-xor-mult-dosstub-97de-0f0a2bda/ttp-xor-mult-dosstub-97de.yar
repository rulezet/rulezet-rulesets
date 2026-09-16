rule TTP_XOR_MULT_DOSStub_97de {
  strings:
    $key_97de = { c3 b6 [2] b7 ae [2] f0 ac [2] b7 bd [2] f9 b1 [2] f5 bb [2] e2 b0 [2] f9 fe [2] c4 }

  condition:
    any of them
}