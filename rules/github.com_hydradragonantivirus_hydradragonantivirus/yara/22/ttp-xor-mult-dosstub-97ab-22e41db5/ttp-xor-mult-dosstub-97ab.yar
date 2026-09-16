rule TTP_XOR_MULT_DOSStub_97ab {
  strings:
    $key_97ab = { c3 c3 [2] b7 db [2] f0 d9 [2] b7 c8 [2] f9 c4 [2] f5 ce [2] e2 c5 [2] f9 8b [2] c4 }

  condition:
    any of them
}