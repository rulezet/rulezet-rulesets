rule TTP_XOR_MULT_DOSStub_d1c4 {
  strings:
    $key_d1c4 = { 85 ac [2] f1 b4 [2] b6 b6 [2] f1 a7 [2] bf ab [2] b3 a1 [2] a4 aa [2] bf e4 [2] 82 }

  condition:
    any of them
}