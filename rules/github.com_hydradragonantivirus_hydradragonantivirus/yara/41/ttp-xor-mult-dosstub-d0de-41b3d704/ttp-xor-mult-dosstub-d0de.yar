rule TTP_XOR_MULT_DOSStub_d0de {
  strings:
    $key_d0de = { 84 b6 [2] f0 ae [2] b7 ac [2] f0 bd [2] be b1 [2] b2 bb [2] a5 b0 [2] be fe [2] 83 }

  condition:
    any of them
}