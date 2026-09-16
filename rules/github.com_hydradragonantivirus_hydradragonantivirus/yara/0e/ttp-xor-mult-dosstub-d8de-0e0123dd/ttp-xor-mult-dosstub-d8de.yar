rule TTP_XOR_MULT_DOSStub_d8de {
  strings:
    $key_d8de = { 8c b6 [2] f8 ae [2] bf ac [2] f8 bd [2] b6 b1 [2] ba bb [2] ad b0 [2] b6 fe [2] 8b }

  condition:
    any of them
}