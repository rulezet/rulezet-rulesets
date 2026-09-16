rule TTP_XOR_MULT_DOSStub_99bd {
  strings:
    $key_99bd = { cd d5 [2] b9 cd [2] fe cf [2] b9 de [2] f7 d2 [2] fb d8 [2] ec d3 [2] f7 9d [2] ca }

  condition:
    any of them
}