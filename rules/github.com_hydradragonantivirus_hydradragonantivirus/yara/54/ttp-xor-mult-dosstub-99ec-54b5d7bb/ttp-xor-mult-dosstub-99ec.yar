rule TTP_XOR_MULT_DOSStub_99ec {
  strings:
    $key_99ec = { cd 84 [2] b9 9c [2] fe 9e [2] b9 8f [2] f7 83 [2] fb 89 [2] ec 82 [2] f7 cc [2] ca }

  condition:
    any of them
}