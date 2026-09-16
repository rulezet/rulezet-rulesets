rule TTP_XOR_MULT_DOSStub_36c2 {
  strings:
    $key_36c2 = { 62 aa [2] 16 b2 [2] 51 b0 [2] 16 a1 [2] 58 ad [2] 54 a7 [2] 43 ac [2] 58 e2 [2] 65 }

  condition:
    any of them
}