rule TTP_XOR_MULT_DOSStub_d586 {
  strings:
    $key_d586 = { 81 ee [2] f5 f6 [2] b2 f4 [2] f5 e5 [2] bb e9 [2] b7 e3 [2] a0 e8 [2] bb a6 [2] 86 }

  condition:
    any of them
}