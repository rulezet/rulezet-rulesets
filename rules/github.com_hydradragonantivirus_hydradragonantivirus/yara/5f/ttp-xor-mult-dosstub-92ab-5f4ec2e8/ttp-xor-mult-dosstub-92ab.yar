rule TTP_XOR_MULT_DOSStub_92ab {
  strings:
    $key_92ab = { c6 c3 [2] b2 db [2] f5 d9 [2] b2 c8 [2] fc c4 [2] f0 ce [2] e7 c5 [2] fc 8b [2] c1 }

  condition:
    any of them
}