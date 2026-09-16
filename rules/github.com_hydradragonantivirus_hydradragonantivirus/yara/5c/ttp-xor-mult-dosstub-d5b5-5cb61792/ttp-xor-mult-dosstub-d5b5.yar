rule TTP_XOR_MULT_DOSStub_d5b5 {
  strings:
    $key_d5b5 = { 81 dd [2] f5 c5 [2] b2 c7 [2] f5 d6 [2] bb da [2] b7 d0 [2] a0 db [2] bb 95 [2] 86 }

  condition:
    any of them
}