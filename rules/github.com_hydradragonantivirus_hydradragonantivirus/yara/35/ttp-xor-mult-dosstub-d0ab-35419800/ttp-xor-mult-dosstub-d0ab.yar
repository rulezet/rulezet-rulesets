rule TTP_XOR_MULT_DOSStub_d0ab {
  strings:
    $key_d0ab = { 84 c3 [2] f0 db [2] b7 d9 [2] f0 c8 [2] be c4 [2] b2 ce [2] a5 c5 [2] be 8b [2] 83 }

  condition:
    any of them
}