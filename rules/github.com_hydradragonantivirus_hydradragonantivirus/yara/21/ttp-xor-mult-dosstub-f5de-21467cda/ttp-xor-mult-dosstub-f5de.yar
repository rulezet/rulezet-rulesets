rule TTP_XOR_MULT_DOSStub_f5de {
  strings:
    $key_f5de = { a1 b6 [2] d5 ae [2] 92 ac [2] d5 bd [2] 9b b1 [2] 97 bb [2] 80 b0 [2] 9b fe [2] a6 }

  condition:
    any of them
}