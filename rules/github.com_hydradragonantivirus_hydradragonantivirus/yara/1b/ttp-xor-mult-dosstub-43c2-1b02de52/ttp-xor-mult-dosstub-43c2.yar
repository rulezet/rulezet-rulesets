rule TTP_XOR_MULT_DOSStub_43c2 {
  strings:
    $key_43c2 = { 17 aa [2] 63 b2 [2] 24 b0 [2] 63 a1 [2] 2d ad [2] 21 a7 [2] 36 ac [2] 2d e2 [2] 10 }

  condition:
    any of them
}