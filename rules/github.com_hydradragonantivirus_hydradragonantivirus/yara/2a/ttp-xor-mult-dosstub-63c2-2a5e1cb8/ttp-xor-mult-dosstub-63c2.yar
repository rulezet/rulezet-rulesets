rule TTP_XOR_MULT_DOSStub_63c2 {
  strings:
    $key_63c2 = { 37 aa [2] 43 b2 [2] 04 b0 [2] 43 a1 [2] 0d ad [2] 01 a7 [2] 16 ac [2] 0d e2 [2] 30 }

  condition:
    any of them
}