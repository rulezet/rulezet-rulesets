rule TTP_XOR_MULT_DOSStub_d5b2 {
  strings:
    $key_d5b2 = { 81 da [2] f5 c2 [2] b2 c0 [2] f5 d1 [2] bb dd [2] b7 d7 [2] a0 dc [2] bb 92 [2] 86 }

  condition:
    any of them
}