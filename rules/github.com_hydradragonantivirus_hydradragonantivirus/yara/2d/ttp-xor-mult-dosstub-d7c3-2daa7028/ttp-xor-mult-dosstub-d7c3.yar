rule TTP_XOR_MULT_DOSStub_d7c3 {
  strings:
    $key_d7c3 = { 83 ab [2] f7 b3 [2] b0 b1 [2] f7 a0 [2] b9 ac [2] b5 a6 [2] a2 ad [2] b9 e3 [2] 84 }

  condition:
    any of them
}