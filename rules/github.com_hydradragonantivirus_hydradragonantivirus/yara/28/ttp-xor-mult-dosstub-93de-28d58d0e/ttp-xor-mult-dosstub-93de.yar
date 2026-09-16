rule TTP_XOR_MULT_DOSStub_93de {
  strings:
    $key_93de = { c7 b6 [2] b3 ae [2] f4 ac [2] b3 bd [2] fd b1 [2] f1 bb [2] e6 b0 [2] fd fe [2] c0 }

  condition:
    any of them
}