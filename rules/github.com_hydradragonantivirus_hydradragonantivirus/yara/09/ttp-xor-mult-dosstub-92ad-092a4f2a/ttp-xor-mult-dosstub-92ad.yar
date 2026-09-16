rule TTP_XOR_MULT_DOSStub_92ad {
  strings:
    $key_92ad = { c6 c5 [2] b2 dd [2] f5 df [2] b2 ce [2] fc c2 [2] f0 c8 [2] e7 c3 [2] fc 8d [2] c1 }

  condition:
    any of them
}