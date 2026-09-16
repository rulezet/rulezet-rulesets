rule TTP_XOR_MULT_DOSStub_9bbc {
  strings:
    $key_9bbc = { cf d4 [2] bb cc [2] fc ce [2] bb df [2] f5 d3 [2] f9 d9 [2] ee d2 [2] f5 9c [2] c8 }

  condition:
    any of them
}