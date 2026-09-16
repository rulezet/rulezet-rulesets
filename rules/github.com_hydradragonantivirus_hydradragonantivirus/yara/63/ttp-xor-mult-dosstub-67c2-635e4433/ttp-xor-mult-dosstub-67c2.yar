rule TTP_XOR_MULT_DOSStub_67c2 {
  strings:
    $key_67c2 = { 33 aa [2] 47 b2 [2] 00 b0 [2] 47 a1 [2] 09 ad [2] 05 a7 [2] 12 ac [2] 09 e2 [2] 34 }

  condition:
    any of them
}