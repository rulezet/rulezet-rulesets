rule TTP_XOR_MULT_DOSStub_95a9 {
  strings:
    $key_95a9 = { c1 c1 [2] b5 d9 [2] f2 db [2] b5 ca [2] fb c6 [2] f7 cc [2] e0 c7 [2] fb 89 [2] c6 }

  condition:
    any of them
}