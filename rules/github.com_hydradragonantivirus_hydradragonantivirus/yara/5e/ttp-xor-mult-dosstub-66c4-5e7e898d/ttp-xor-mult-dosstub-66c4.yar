rule TTP_XOR_MULT_DOSStub_66c4 {
  strings:
    $key_66c4 = { 32 ac [2] 46 b4 [2] 01 b6 [2] 46 a7 [2] 08 ab [2] 04 a1 [2] 13 aa [2] 08 e4 [2] 35 }

  condition:
    any of them
}