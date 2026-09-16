rule TTP_XOR_MULT_DOSStub_95a2 {
  strings:
    $key_95a2 = { c1 ca [2] b5 d2 [2] f2 d0 [2] b5 c1 [2] fb cd [2] f7 c7 [2] e0 cc [2] fb 82 [2] c6 }

  condition:
    any of them
}