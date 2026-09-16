rule TTP_XOR_MULT_DOSStub_9fbe {
  strings:
    $key_9fbe = { cb d6 [2] bf ce [2] f8 cc [2] bf dd [2] f1 d1 [2] fd db [2] ea d0 [2] f1 9e [2] cc }

  condition:
    any of them
}