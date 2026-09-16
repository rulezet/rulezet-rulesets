rule TTP_XOR_MULT_DOSStub_9fbb {
  strings:
    $key_9fbb = { cb d3 [2] bf cb [2] f8 c9 [2] bf d8 [2] f1 d4 [2] fd de [2] ea d5 [2] f1 9b [2] cc }

  condition:
    any of them
}