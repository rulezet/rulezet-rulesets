rule TTP_XOR_MULT_DOSStub_76c4 {
  strings:
    $key_76c4 = { 22 ac [2] 56 b4 [2] 11 b6 [2] 56 a7 [2] 18 ab [2] 14 a1 [2] 03 aa [2] 18 e4 [2] 25 }

  condition:
    any of them
}