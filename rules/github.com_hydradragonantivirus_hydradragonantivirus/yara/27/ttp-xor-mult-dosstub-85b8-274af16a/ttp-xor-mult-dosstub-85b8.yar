rule TTP_XOR_MULT_DOSStub_85b8 {
  strings:
    $key_85b8 = { d1 d0 [2] a5 c8 [2] e2 ca [2] a5 db [2] eb d7 [2] e7 dd [2] f0 d6 [2] eb 98 [2] d6 }

  condition:
    any of them
}