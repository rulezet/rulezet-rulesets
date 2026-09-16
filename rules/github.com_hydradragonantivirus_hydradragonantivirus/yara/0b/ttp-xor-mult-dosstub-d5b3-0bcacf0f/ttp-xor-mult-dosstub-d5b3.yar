rule TTP_XOR_MULT_DOSStub_d5b3 {
  strings:
    $key_d5b3 = { 81 db [2] f5 c3 [2] b2 c1 [2] f5 d0 [2] bb dc [2] b7 d6 [2] a0 dd [2] bb 93 [2] 86 }

  condition:
    any of them
}