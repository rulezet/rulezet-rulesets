rule TTP_XOR_MULT_DOSStub_99a4 {
  strings:
    $key_99a4 = { cd cc [2] b9 d4 [2] fe d6 [2] b9 c7 [2] f7 cb [2] fb c1 [2] ec ca [2] f7 84 [2] ca }

  condition:
    any of them
}