rule TTP_XOR_MULT_DOSStub_03c4 {
  strings:
    $key_03c4 = { 57 ac [2] 23 b4 [2] 64 b6 [2] 23 a7 [2] 6d ab [2] 61 a1 [2] 76 aa [2] 6d e4 [2] 50 }

  condition:
    any of them
}