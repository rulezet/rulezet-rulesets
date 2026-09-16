rule TTP_XOR_MULT_DOSStub_42c9 {
  strings:
    $key_42c9 = { 16 a1 [2] 62 b9 [2] 25 bb [2] 62 aa [2] 2c a6 [2] 20 ac [2] 37 a7 [2] 2c e9 [2] 11 }

  condition:
    any of them
}