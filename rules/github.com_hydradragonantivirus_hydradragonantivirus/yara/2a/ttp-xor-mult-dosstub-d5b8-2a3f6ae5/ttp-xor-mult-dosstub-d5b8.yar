rule TTP_XOR_MULT_DOSStub_d5b8 {
  strings:
    $key_d5b8 = { 81 d0 [2] f5 c8 [2] b2 ca [2] f5 db [2] bb d7 [2] b7 dd [2] a0 d6 [2] bb 98 [2] 86 }

  condition:
    any of them
}