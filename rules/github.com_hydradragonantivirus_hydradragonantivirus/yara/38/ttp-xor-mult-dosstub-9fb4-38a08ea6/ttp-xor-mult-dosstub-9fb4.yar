rule TTP_XOR_MULT_DOSStub_9fb4 {
  strings:
    $key_9fb4 = { cb dc [2] bf c4 [2] f8 c6 [2] bf d7 [2] f1 db [2] fd d1 [2] ea da [2] f1 94 [2] cc }

  condition:
    any of them
}