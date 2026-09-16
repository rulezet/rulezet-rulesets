rule TTP_XOR_MULT_DOSStub_99ac {
  strings:
    $key_99ac = { cd c4 [2] b9 dc [2] fe de [2] b9 cf [2] f7 c3 [2] fb c9 [2] ec c2 [2] f7 8c [2] ca }

  condition:
    any of them
}