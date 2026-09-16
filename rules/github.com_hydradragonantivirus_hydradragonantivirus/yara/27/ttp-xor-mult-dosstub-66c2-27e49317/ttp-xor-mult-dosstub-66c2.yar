rule TTP_XOR_MULT_DOSStub_66c2 {
  strings:
    $key_66c2 = { 32 aa [2] 46 b2 [2] 01 b0 [2] 46 a1 [2] 08 ad [2] 04 a7 [2] 13 ac [2] 08 e2 [2] 35 }

  condition:
    any of them
}