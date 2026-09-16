rule TTP_XOR_MULT_DOSStub_99b6 {
  strings:
    $key_99b6 = { cd de [2] b9 c6 [2] fe c4 [2] b9 d5 [2] f7 d9 [2] fb d3 [2] ec d8 [2] f7 96 [2] ca }

  condition:
    any of them
}