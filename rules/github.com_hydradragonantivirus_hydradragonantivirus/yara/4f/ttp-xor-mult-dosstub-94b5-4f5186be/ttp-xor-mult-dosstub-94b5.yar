rule TTP_XOR_MULT_DOSStub_94b5 {
  strings:
    $key_94b5 = { c0 dd [2] b4 c5 [2] f3 c7 [2] b4 d6 [2] fa da [2] f6 d0 [2] e1 db [2] fa 95 [2] c7 }

  condition:
    any of them
}