rule TTP_XOR_MULT_DOSStub_d5c7 {
  strings:
    $key_d5c7 = { 81 af [2] f5 b7 [2] b2 b5 [2] f5 a4 [2] bb a8 [2] b7 a2 [2] a0 a9 [2] bb e7 [2] 86 }

  condition:
    any of them
}