rule TTP_XOR_MULT_DOSStub_62c4 {
  strings:
    $key_62c4 = { 36 ac [2] 42 b4 [2] 05 b6 [2] 42 a7 [2] 0c ab [2] 00 a1 [2] 17 aa [2] 0c e4 [2] 31 }

  condition:
    any of them
}