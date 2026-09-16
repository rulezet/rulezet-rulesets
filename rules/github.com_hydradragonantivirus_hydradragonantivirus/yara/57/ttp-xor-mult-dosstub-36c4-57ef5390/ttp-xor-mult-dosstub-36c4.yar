rule TTP_XOR_MULT_DOSStub_36c4 {
  strings:
    $key_36c4 = { 62 ac [2] 16 b4 [2] 51 b6 [2] 16 a7 [2] 58 ab [2] 54 a1 [2] 43 aa [2] 58 e4 [2] 65 }

  condition:
    any of them
}