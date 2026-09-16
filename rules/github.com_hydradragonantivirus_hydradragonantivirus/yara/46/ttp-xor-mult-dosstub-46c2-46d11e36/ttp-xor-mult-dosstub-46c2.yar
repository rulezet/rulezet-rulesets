rule TTP_XOR_MULT_DOSStub_46c2 {
  strings:
    $key_46c2 = { 12 aa [2] 66 b2 [2] 21 b0 [2] 66 a1 [2] 28 ad [2] 24 a7 [2] 33 ac [2] 28 e2 [2] 15 }

  condition:
    any of them
}