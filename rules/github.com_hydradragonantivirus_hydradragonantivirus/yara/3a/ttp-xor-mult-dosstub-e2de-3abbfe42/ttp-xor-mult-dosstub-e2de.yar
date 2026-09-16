rule TTP_XOR_MULT_DOSStub_e2de {
  strings:
    $key_e2de = { b6 b6 [2] c2 ae [2] 85 ac [2] c2 bd [2] 8c b1 [2] 80 bb [2] 97 b0 [2] 8c fe [2] b1 }

  condition:
    any of them
}