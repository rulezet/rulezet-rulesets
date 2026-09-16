rule TTP_XOR_MULT_DOSStub_14c9 {
  strings:
    $key_14c9 = { 40 a1 [2] 34 b9 [2] 73 bb [2] 34 aa [2] 7a a6 [2] 76 ac [2] 61 a7 [2] 7a e9 [2] 47 }

  condition:
    any of them
}