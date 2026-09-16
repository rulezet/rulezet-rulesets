rule TTP_XOR_MULT_DOSStub_73c9 {
  strings:
    $key_73c9 = { 27 a1 [2] 53 b9 [2] 14 bb [2] 53 aa [2] 1d a6 [2] 11 ac [2] 06 a7 [2] 1d e9 [2] 20 }

  condition:
    any of them
}