rule TTP_XOR_MULT_DOSStub_95a0 {
  strings:
    $key_95a0 = { c1 c8 [2] b5 d0 [2] f2 d2 [2] b5 c3 [2] fb cf [2] f7 c5 [2] e0 ce [2] fb 80 [2] c6 }

  condition:
    any of them
}