rule TTP_XOR_MULT_DOSStub_33c2 {
  strings:
    $key_33c2 = { 67 aa [2] 13 b2 [2] 54 b0 [2] 13 a1 [2] 5d ad [2] 51 a7 [2] 46 ac [2] 5d e2 [2] 60 }

  condition:
    any of them
}