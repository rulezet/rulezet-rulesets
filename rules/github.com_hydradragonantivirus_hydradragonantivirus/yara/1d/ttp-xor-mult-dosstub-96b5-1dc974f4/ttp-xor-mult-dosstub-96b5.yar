rule TTP_XOR_MULT_DOSStub_96b5 {
  strings:
    $key_96b5 = { c2 dd [2] b6 c5 [2] f1 c7 [2] b6 d6 [2] f8 da [2] f4 d0 [2] e3 db [2] f8 95 [2] c5 }

  condition:
    any of them
}