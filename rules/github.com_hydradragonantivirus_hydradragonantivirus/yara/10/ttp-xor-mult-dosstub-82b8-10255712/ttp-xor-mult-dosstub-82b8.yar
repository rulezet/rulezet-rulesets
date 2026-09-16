rule TTP_XOR_MULT_DOSStub_82b8 {
  strings:
    $key_82b8 = { d6 d0 [2] a2 c8 [2] e5 ca [2] a2 db [2] ec d7 [2] e0 dd [2] f7 d6 [2] ec 98 [2] d1 }

  condition:
    any of them
}