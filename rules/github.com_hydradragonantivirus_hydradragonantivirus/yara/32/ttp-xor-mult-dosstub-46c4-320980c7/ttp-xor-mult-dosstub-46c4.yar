rule TTP_XOR_MULT_DOSStub_46c4 {
  strings:
    $key_46c4 = { 12 ac [2] 66 b4 [2] 21 b6 [2] 66 a7 [2] 28 ab [2] 24 a1 [2] 33 aa [2] 28 e4 [2] 15 }

  condition:
    any of them
}