rule TTP_XOR_MULT_DOSStub_9fac {
  strings:
    $key_9fac = { cb c4 [2] bf dc [2] f8 de [2] bf cf [2] f1 c3 [2] fd c9 [2] ea c2 [2] f1 8c [2] cc }

  condition:
    any of them
}