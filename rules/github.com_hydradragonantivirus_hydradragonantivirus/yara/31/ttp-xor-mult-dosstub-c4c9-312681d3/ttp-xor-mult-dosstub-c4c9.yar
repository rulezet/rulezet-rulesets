rule TTP_XOR_MULT_DOSStub_c4c9 {
  strings:
    $key_c4c9 = { 90 a1 [2] e4 b9 [2] a3 bb [2] e4 aa [2] aa a6 [2] a6 ac [2] b1 a7 [2] aa e9 [2] 97 }

  condition:
    any of them
}