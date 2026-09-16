rule TTP_XOR_MULT_DOSStub_d1de {
  strings:
    $key_d1de = { 85 b6 [2] f1 ae [2] b6 ac [2] f1 bd [2] bf b1 [2] b3 bb [2] a4 b0 [2] bf fe [2] 82 }

  condition:
    any of them
}