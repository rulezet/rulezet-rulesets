rule TTP_XOR_MULT_DOSStub_d2de {
  strings:
    $key_d2de = { 86 b6 [2] f2 ae [2] b5 ac [2] f2 bd [2] bc b1 [2] b0 bb [2] a7 b0 [2] bc fe [2] 81 }

  condition:
    any of them
}