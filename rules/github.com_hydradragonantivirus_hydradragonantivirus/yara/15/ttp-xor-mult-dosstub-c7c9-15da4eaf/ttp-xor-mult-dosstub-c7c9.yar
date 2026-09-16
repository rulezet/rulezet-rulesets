rule TTP_XOR_MULT_DOSStub_c7c9 {
  strings:
    $key_c7c9 = { 93 a1 [2] e7 b9 [2] a0 bb [2] e7 aa [2] a9 a6 [2] a5 ac [2] b2 a7 [2] a9 e9 [2] 94 }

  condition:
    any of them
}