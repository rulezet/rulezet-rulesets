rule TTP_XOR_MULT_DOSStub_d5a6 {
  strings:
    $key_d5a6 = { 81 ce [2] f5 d6 [2] b2 d4 [2] f5 c5 [2] bb c9 [2] b7 c3 [2] a0 c8 [2] bb 86 [2] 86 }

  condition:
    any of them
}