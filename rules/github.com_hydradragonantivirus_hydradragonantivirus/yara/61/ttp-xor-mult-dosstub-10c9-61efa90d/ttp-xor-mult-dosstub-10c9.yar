rule TTP_XOR_MULT_DOSStub_10c9 {
  strings:
    $key_10c9 = { 44 a1 [2] 30 b9 [2] 77 bb [2] 30 aa [2] 7e a6 [2] 72 ac [2] 65 a7 [2] 7e e9 [2] 43 }

  condition:
    any of them
}