rule TTP_XOR_MULT_DOSStub_9cb3 {
  strings:
    $key_9cb3 = { c8 db [2] bc c3 [2] fb c1 [2] bc d0 [2] f2 dc [2] fe d6 [2] e9 dd [2] f2 93 [2] cf }

  condition:
    any of them
}