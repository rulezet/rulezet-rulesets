rule TTP_XOR_MULT_DOSStub_99aa {
  strings:
    $key_99aa = { cd c2 [2] b9 da [2] fe d8 [2] b9 c9 [2] f7 c5 [2] fb cf [2] ec c4 [2] f7 8a [2] ca }

  condition:
    any of them
}