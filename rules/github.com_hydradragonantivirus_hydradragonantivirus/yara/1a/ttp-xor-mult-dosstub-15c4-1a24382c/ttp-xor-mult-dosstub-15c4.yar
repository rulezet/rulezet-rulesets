rule TTP_XOR_MULT_DOSStub_15c4 {
  strings:
    $key_15c4 = { 41 ac [2] 35 b4 [2] 72 b6 [2] 35 a7 [2] 7b ab [2] 77 a1 [2] 60 aa [2] 7b e4 [2] 46 }

  condition:
    any of them
}