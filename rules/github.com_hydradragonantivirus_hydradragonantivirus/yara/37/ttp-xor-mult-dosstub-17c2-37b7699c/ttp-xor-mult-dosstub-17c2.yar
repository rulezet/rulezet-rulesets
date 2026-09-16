rule TTP_XOR_MULT_DOSStub_17c2 {
  strings:
    $key_17c2 = { 43 aa [2] 37 b2 [2] 70 b0 [2] 37 a1 [2] 79 ad [2] 75 a7 [2] 62 ac [2] 79 e2 [2] 44 }

  condition:
    any of them
}