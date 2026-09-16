rule TTP_XOR_MULT_DOSStub_77c9 {
  strings:
    $key_77c9 = { 23 a1 [2] 57 b9 [2] 10 bb [2] 57 aa [2] 19 a6 [2] 15 ac [2] 02 a7 [2] 19 e9 [2] 24 }

  condition:
    any of them
}