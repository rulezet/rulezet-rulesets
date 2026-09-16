rule TTP_XOR_MULT_DOSStub_d3de {
  strings:
    $key_d3de = { 87 b6 [2] f3 ae [2] b4 ac [2] f3 bd [2] bd b1 [2] b1 bb [2] a6 b0 [2] bd fe [2] 80 }

  condition:
    any of them
}