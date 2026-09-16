rule TTP_XOR_MULT_DOSStub_55c9 {
  strings:
    $key_55c9 = { 01 a1 [2] 75 b9 [2] 32 bb [2] 75 aa [2] 3b a6 [2] 37 ac [2] 20 a7 [2] 3b e9 [2] 06 }

  condition:
    any of them
}