rule TTP_XOR_MULT_DOSStub_d587 {
  strings:
    $key_d587 = { 81 ef [2] f5 f7 [2] b2 f5 [2] f5 e4 [2] bb e8 [2] b7 e2 [2] a0 e9 [2] bb a7 [2] 86 }

  condition:
    any of them
}