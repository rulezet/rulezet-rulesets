rule TTP_XOR_MULT_DOSStub_73c2 {
  strings:
    $key_73c2 = { 27 aa [2] 53 b2 [2] 14 b0 [2] 53 a1 [2] 1d ad [2] 11 a7 [2] 06 ac [2] 1d e2 [2] 20 }

  condition:
    any of them
}