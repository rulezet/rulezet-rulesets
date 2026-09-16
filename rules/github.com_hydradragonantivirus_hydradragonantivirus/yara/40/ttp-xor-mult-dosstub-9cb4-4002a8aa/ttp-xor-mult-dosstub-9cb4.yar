rule TTP_XOR_MULT_DOSStub_9cb4 {
  strings:
    $key_9cb4 = { c8 dc [2] bc c4 [2] fb c6 [2] bc d7 [2] f2 db [2] fe d1 [2] e9 da [2] f2 94 [2] cf }

  condition:
    any of them
}