rule TTP_XOR_MULT_DOSStub_75c4 {
  strings:
    $key_75c4 = { 21 ac [2] 55 b4 [2] 12 b6 [2] 55 a7 [2] 1b ab [2] 17 a1 [2] 00 aa [2] 1b e4 [2] 26 }

  condition:
    any of them
}