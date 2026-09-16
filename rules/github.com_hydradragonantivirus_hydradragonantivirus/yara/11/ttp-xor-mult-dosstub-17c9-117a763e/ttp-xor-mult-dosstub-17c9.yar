rule TTP_XOR_MULT_DOSStub_17c9 {
  strings:
    $key_17c9 = { 43 a1 [2] 37 b9 [2] 70 bb [2] 37 aa [2] 79 a6 [2] 75 ac [2] 62 a7 [2] 79 e9 [2] 44 }

  condition:
    any of them
}