rule TTP_XOR_MULT_DOSStub_94de {
  strings:
    $key_94de = { c0 b6 [2] b4 ae [2] f3 ac [2] b4 bd [2] fa b1 [2] f6 bb [2] e1 b0 [2] fa fe [2] c7 }

  condition:
    any of them
}