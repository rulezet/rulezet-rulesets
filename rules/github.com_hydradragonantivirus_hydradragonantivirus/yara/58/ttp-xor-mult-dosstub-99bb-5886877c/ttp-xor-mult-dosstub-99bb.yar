rule TTP_XOR_MULT_DOSStub_99bb {
  strings:
    $key_99bb = { cd d3 [2] b9 cb [2] fe c9 [2] b9 d8 [2] f7 d4 [2] fb de [2] ec d5 [2] f7 9b [2] ca }

  condition:
    any of them
}