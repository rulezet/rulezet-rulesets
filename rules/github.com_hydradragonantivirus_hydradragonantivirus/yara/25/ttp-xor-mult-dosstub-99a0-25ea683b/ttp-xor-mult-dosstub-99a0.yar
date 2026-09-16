rule TTP_XOR_MULT_DOSStub_99a0 {
  strings:
    $key_99a0 = { cd c8 [2] b9 d0 [2] fe d2 [2] b9 c3 [2] f7 cf [2] fb c5 [2] ec ce [2] f7 80 [2] ca }

  condition:
    any of them
}