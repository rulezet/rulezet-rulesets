rule TTP_XOR_MULT_DOSStub_50c9 {
  strings:
    $key_50c9 = { 04 a1 [2] 70 b9 [2] 37 bb [2] 70 aa [2] 3e a6 [2] 32 ac [2] 25 a7 [2] 3e e9 [2] 03 }

  condition:
    any of them
}