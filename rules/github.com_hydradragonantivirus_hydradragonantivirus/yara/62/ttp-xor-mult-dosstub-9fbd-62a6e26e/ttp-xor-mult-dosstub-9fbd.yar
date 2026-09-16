rule TTP_XOR_MULT_DOSStub_9fbd {
  strings:
    $key_9fbd = { cb d5 [2] bf cd [2] f8 cf [2] bf de [2] f1 d2 [2] fd d8 [2] ea d3 [2] f1 9d [2] cc }

  condition:
    any of them
}