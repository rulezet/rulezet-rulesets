rule TTP_XOR_MULT_DOSStub_d1c9 {
  strings:
    $key_d1c9 = { 85 a1 [2] f1 b9 [2] b6 bb [2] f1 aa [2] bf a6 [2] b3 ac [2] a4 a7 [2] bf e9 [2] 82 }

  condition:
    any of them
}