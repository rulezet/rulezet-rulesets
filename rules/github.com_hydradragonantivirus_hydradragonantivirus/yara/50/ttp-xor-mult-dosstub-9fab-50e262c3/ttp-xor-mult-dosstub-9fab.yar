rule TTP_XOR_MULT_DOSStub_9fab {
  strings:
    $key_9fab = { cb c3 [2] bf db [2] f8 d9 [2] bf c8 [2] f1 c4 [2] fd ce [2] ea c5 [2] f1 8b [2] cc }

  condition:
    any of them
}