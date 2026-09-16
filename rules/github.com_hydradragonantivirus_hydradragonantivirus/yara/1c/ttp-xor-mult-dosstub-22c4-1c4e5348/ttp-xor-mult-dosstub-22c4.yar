rule TTP_XOR_MULT_DOSStub_22c4 {
  strings:
    $key_22c4 = { 76 ac [2] 02 b4 [2] 45 b6 [2] 02 a7 [2] 4c ab [2] 40 a1 [2] 57 aa [2] 4c e4 [2] 71 }

  condition:
    any of them
}