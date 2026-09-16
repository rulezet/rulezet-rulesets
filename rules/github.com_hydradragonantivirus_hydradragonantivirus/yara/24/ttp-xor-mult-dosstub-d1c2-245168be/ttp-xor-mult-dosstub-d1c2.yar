rule TTP_XOR_MULT_DOSStub_d1c2 {
  strings:
    $key_d1c2 = { 85 aa [2] f1 b2 [2] b6 b0 [2] f1 a1 [2] bf ad [2] b3 a7 [2] a4 ac [2] bf e2 [2] 82 }

  condition:
    any of them
}