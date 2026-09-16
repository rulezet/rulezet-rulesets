rule TTP_XOR_MULT_DOSStub_d5c6 {
  strings:
    $key_d5c6 = { 81 ae [2] f5 b6 [2] b2 b4 [2] f5 a5 [2] bb a9 [2] b7 a3 [2] a0 a8 [2] bb e6 [2] 86 }

  condition:
    any of them
}