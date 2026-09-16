rule TTP_XOR_MULT_DOSStub_9cb2 {
  strings:
    $key_9cb2 = { c8 da [2] bc c2 [2] fb c0 [2] bc d1 [2] f2 dd [2] fe d7 [2] e9 dc [2] f2 92 [2] cf }

  condition:
    any of them
}