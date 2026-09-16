rule TTP_XOR_MULT_DOSStub_d5c4 {
  strings:
    $key_d5c4 = { 81 ac [2] f5 b4 [2] b2 b6 [2] f5 a7 [2] bb ab [2] b7 a1 [2] a0 aa [2] bb e4 [2] 86 }

  condition:
    any of them
}