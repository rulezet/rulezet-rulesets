rule TTP_XOR_MULT_DOSStub_44c9 {
  strings:
    $key_44c9 = { 10 a1 [2] 64 b9 [2] 23 bb [2] 64 aa [2] 2a a6 [2] 26 ac [2] 31 a7 [2] 2a e9 [2] 17 }

  condition:
    any of them
}