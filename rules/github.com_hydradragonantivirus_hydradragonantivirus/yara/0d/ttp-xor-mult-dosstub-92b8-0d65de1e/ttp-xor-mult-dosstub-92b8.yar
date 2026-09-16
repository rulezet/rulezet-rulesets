rule TTP_XOR_MULT_DOSStub_92b8 {
  strings:
    $key_92b8 = { c6 d0 [2] b2 c8 [2] f5 ca [2] b2 db [2] fc d7 [2] f0 dd [2] e7 d6 [2] fc 98 [2] c1 }

  condition:
    any of them
}