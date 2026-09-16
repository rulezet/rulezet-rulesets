rule TTP_XOR_MULT_DOSStub_73c4 {
  strings:
    $key_73c4 = { 27 ac [2] 53 b4 [2] 14 b6 [2] 53 a7 [2] 1d ab [2] 11 a1 [2] 06 aa [2] 1d e4 [2] 20 }

  condition:
    any of them
}