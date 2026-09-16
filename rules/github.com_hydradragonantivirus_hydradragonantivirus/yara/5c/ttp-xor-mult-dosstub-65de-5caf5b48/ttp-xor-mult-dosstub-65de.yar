rule TTP_XOR_MULT_DOSStub_65de {
  strings:
    $key_65de = { 31 b6 [2] 45 ae [2] 02 ac [2] 45 bd [2] 0b b1 [2] 07 bb [2] 10 b0 [2] 0b fe [2] 36 }

  condition:
    any of them
}