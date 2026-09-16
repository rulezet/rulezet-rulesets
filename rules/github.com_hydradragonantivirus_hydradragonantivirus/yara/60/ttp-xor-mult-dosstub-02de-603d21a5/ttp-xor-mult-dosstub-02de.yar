rule TTP_XOR_MULT_DOSStub_02de {
  strings:
    $key_02de = { 56 b6 [2] 22 ae [2] 65 ac [2] 22 bd [2] 6c b1 [2] 60 bb [2] 77 b0 [2] 6c fe [2] 51 }

  condition:
    any of them
}