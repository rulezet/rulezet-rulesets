rule TTP_XOR_MULT_DOSStub_92de {
  strings:
    $key_92de = { c6 b6 [2] b2 ae [2] f5 ac [2] b2 bd [2] fc b1 [2] f0 bb [2] e7 b0 [2] fc fe [2] c1 }

  condition:
    any of them
}