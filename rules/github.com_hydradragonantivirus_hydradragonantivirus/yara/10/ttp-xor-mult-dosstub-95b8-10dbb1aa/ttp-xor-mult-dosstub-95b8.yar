rule TTP_XOR_MULT_DOSStub_95b8 {
  strings:
    $key_95b8 = { c1 d0 [2] b5 c8 [2] f2 ca [2] b5 db [2] fb d7 [2] f7 dd [2] e0 d6 [2] fb 98 [2] c6 }

  condition:
    any of them
}