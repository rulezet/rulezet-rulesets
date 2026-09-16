rule TTP_XOR_MULT_DOSStub_34c9 {
  strings:
    $key_34c9 = { 60 a1 [2] 14 b9 [2] 53 bb [2] 14 aa [2] 5a a6 [2] 56 ac [2] 41 a7 [2] 5a e9 [2] 67 }

  condition:
    any of them
}