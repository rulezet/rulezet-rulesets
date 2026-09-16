rule TTP_XOR_MULT_DOSStub_9faa {
  strings:
    $key_9faa = { cb c2 [2] bf da [2] f8 d8 [2] bf c9 [2] f1 c5 [2] fd cf [2] ea c4 [2] f1 8a [2] cc }

  condition:
    any of them
}