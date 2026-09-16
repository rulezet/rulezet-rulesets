rule TTP_XOR_MULT_DOSStub_99a9 {
  strings:
    $key_99a9 = { cd c1 [2] b9 d9 [2] fe db [2] b9 ca [2] f7 c6 [2] fb cc [2] ec c7 [2] f7 89 [2] ca }

  condition:
    any of them
}