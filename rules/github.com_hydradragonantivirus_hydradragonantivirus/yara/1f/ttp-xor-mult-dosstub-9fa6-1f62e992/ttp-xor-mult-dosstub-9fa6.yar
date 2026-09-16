rule TTP_XOR_MULT_DOSStub_9fa6 {
  strings:
    $key_9fa6 = { cb ce [2] bf d6 [2] f8 d4 [2] bf c5 [2] f1 c9 [2] fd c3 [2] ea c8 [2] f1 86 [2] cc }

  condition:
    any of them
}