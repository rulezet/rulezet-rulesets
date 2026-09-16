rule TTP_XOR_MULT_DOSStub_99d2 {
  strings:
    $key_99d2 = { cd ba [2] b9 a2 [2] fe a0 [2] b9 b1 [2] f7 bd [2] fb b7 [2] ec bc [2] f7 f2 [2] ca }

  condition:
    any of them
}