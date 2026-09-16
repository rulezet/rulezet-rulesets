rule TTP_XOR_MULT_DOSStub_40c4 {
  strings:
    $key_40c4 = { 14 ac [2] 60 b4 [2] 27 b6 [2] 60 a7 [2] 2e ab [2] 22 a1 [2] 35 aa [2] 2e e4 [2] 13 }

  condition:
    any of them
}