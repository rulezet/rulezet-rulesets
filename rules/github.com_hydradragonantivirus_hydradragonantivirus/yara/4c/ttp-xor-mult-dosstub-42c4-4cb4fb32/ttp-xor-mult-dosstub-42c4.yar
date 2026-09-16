rule TTP_XOR_MULT_DOSStub_42c4 {
  strings:
    $key_42c4 = { 16 ac [2] 62 b4 [2] 25 b6 [2] 62 a7 [2] 2c ab [2] 20 a1 [2] 37 aa [2] 2c e4 [2] 11 }

  condition:
    any of them
}