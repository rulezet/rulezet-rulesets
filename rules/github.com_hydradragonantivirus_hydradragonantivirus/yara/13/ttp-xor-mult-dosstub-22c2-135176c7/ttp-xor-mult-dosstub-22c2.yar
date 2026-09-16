rule TTP_XOR_MULT_DOSStub_22c2 {
  strings:
    $key_22c2 = { 76 aa [2] 02 b2 [2] 45 b0 [2] 02 a1 [2] 4c ad [2] 40 a7 [2] 57 ac [2] 4c e2 [2] 71 }

  condition:
    any of them
}