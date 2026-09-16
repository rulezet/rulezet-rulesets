rule TTP_XOR_MULT_DOSStub_95ab {
  strings:
    $key_95ab = { c1 c3 [2] b5 db [2] f2 d9 [2] b5 c8 [2] fb c4 [2] f7 ce [2] e0 c5 [2] fb 8b [2] c6 }

  condition:
    any of them
}