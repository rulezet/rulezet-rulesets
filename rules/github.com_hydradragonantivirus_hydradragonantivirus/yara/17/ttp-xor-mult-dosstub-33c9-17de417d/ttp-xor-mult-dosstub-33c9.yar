rule TTP_XOR_MULT_DOSStub_33c9 {
  strings:
    $key_33c9 = { 67 a1 [2] 13 b9 [2] 54 bb [2] 13 aa [2] 5d a6 [2] 51 ac [2] 46 a7 [2] 5d e9 [2] 60 }

  condition:
    any of them
}