rule TTP_XOR_MULT_DOSStub_99a6 {
  strings:
    $key_99a6 = { cd ce [2] b9 d6 [2] fe d4 [2] b9 c5 [2] f7 c9 [2] fb c3 [2] ec c8 [2] f7 86 [2] ca }

  condition:
    any of them
}