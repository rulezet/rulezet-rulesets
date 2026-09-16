rule TTP_XOR_MULT_DOSStub_c6c9 {
  strings:
    $key_c6c9 = { 92 a1 [2] e6 b9 [2] a1 bb [2] e6 aa [2] a8 a6 [2] a4 ac [2] b3 a7 [2] a8 e9 [2] 95 }

  condition:
    any of them
}