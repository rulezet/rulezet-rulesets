rule TTP_XOR_MULT_DOSStub_a4de {
  strings:
    $key_a4de = { f0 b6 [2] 84 ae [2] c3 ac [2] 84 bd [2] ca b1 [2] c6 bb [2] d1 b0 [2] ca fe [2] f7 }

  condition:
    any of them
}