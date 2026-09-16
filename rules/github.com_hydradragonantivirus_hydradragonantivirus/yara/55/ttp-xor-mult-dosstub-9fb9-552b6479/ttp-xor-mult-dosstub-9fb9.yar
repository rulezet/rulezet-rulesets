rule TTP_XOR_MULT_DOSStub_9fb9 {
  strings:
    $key_9fb9 = { cb d1 [2] bf c9 [2] f8 cb [2] bf da [2] f1 d6 [2] fd dc [2] ea d7 [2] f1 99 [2] cc }

  condition:
    any of them
}