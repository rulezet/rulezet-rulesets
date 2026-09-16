rule TTP_XOR_MULT_DOSStub_d588 {
  strings:
    $key_d588 = { 81 e0 [2] f5 f8 [2] b2 fa [2] f5 eb [2] bb e7 [2] b7 ed [2] a0 e6 [2] bb a8 [2] 86 }

  condition:
    any of them
}