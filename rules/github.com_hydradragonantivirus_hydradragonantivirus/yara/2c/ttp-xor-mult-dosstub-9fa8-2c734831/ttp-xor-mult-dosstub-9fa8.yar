rule TTP_XOR_MULT_DOSStub_9fa8 {
  strings:
    $key_9fa8 = { cb c0 [2] bf d8 [2] f8 da [2] bf cb [2] f1 c7 [2] fd cd [2] ea c6 [2] f1 88 [2] cc }

  condition:
    any of them
}