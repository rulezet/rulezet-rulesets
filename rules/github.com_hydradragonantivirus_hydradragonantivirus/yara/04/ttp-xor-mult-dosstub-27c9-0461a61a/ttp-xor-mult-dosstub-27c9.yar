rule TTP_XOR_MULT_DOSStub_27c9 {
  strings:
    $key_27c9 = { 73 a1 [2] 07 b9 [2] 40 bb [2] 07 aa [2] 49 a6 [2] 45 ac [2] 52 a7 [2] 49 e9 [2] 74 }

  condition:
    any of them
}