rule TTP_XOR_MULT_DOSStub_97b3 {
  strings:
    $key_97b3 = { c3 db [2] b7 c3 [2] f0 c1 [2] b7 d0 [2] f9 dc [2] f5 d6 [2] e2 dd [2] f9 93 [2] c4 }

  condition:
    any of them
}