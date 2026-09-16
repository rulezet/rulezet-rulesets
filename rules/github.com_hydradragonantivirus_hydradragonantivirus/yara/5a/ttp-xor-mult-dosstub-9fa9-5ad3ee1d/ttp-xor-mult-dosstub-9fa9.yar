rule TTP_XOR_MULT_DOSStub_9fa9 {
  strings:
    $key_9fa9 = { cb c1 [2] bf d9 [2] f8 db [2] bf ca [2] f1 c6 [2] fd cc [2] ea c7 [2] f1 89 [2] cc }

  condition:
    any of them
}