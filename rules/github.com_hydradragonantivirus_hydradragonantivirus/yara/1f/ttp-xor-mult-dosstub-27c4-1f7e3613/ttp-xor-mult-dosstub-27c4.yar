rule TTP_XOR_MULT_DOSStub_27c4 {
  strings:
    $key_27c4 = { 73 ac [2] 07 b4 [2] 40 b6 [2] 07 a7 [2] 49 ab [2] 45 a1 [2] 52 aa [2] 49 e4 [2] 74 }

  condition:
    any of them
}