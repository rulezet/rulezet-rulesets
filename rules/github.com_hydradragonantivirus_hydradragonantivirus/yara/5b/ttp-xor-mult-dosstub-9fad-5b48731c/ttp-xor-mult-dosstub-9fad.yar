rule TTP_XOR_MULT_DOSStub_9fad {
  strings:
    $key_9fad = { cb c5 [2] bf dd [2] f8 df [2] bf ce [2] f1 c2 [2] fd c8 [2] ea c3 [2] f1 8d [2] cc }

  condition:
    any of them
}