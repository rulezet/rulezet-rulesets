rule TTP_XOR_MULT_DOSStub_67c9 {
  strings:
    $key_67c9 = { 33 a1 [2] 47 b9 [2] 00 bb [2] 47 aa [2] 09 a6 [2] 05 ac [2] 12 a7 [2] 09 e9 [2] 34 }

  condition:
    any of them
}