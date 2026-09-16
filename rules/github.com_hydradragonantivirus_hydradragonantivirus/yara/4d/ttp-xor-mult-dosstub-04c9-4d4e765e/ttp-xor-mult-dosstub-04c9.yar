rule TTP_XOR_MULT_DOSStub_04c9 {
  strings:
    $key_04c9 = { 50 a1 [2] 24 b9 [2] 63 bb [2] 24 aa [2] 6a a6 [2] 66 ac [2] 71 a7 [2] 6a e9 [2] 57 }

  condition:
    any of them
}