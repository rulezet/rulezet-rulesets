rule TTP_XOR_MULT_DOSStub_81de {
  strings:
    $key_81de = { d5 b6 [2] a1 ae [2] e6 ac [2] a1 bd [2] ef b1 [2] e3 bb [2] f4 b0 [2] ef fe [2] d2 }

  condition:
    any of them
}