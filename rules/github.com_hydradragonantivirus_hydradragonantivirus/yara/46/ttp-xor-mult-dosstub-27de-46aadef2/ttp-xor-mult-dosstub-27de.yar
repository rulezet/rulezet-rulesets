rule TTP_XOR_MULT_DOSStub_27de {
  strings:
    $key_27de = { 73 b6 [2] 07 ae [2] 40 ac [2] 07 bd [2] 49 b1 [2] 45 bb [2] 52 b0 [2] 49 fe [2] 74 }

  condition:
    any of them
}