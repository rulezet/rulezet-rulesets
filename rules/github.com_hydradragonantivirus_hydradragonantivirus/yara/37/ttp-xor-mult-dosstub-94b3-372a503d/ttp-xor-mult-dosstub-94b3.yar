rule TTP_XOR_MULT_DOSStub_94b3 {
  strings:
    $key_94b3 = { c0 db [2] b4 c3 [2] f3 c1 [2] b4 d0 [2] fa dc [2] f6 d6 [2] e1 dd [2] fa 93 [2] c7 }

  condition:
    any of them
}