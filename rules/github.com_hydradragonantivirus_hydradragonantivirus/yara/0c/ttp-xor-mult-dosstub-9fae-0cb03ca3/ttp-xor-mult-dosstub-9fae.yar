rule TTP_XOR_MULT_DOSStub_9fae {
  strings:
    $key_9fae = { cb c6 [2] bf de [2] f8 dc [2] bf cd [2] f1 c1 [2] fd cb [2] ea c0 [2] f1 8e [2] cc }

  condition:
    any of them
}