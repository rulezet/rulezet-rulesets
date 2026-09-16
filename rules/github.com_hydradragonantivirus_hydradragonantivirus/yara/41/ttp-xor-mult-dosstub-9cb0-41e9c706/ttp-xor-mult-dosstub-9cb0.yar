rule TTP_XOR_MULT_DOSStub_9cb0 {
  strings:
    $key_9cb0 = { c8 d8 [2] bc c0 [2] fb c2 [2] bc d3 [2] f2 df [2] fe d5 [2] e9 de [2] f2 90 [2] cf }

  condition:
    any of them
}