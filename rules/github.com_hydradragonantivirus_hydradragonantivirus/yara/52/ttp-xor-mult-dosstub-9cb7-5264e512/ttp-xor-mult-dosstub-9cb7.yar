rule TTP_XOR_MULT_DOSStub_9cb7 {
  strings:
    $key_9cb7 = { c8 df [2] bc c7 [2] fb c5 [2] bc d4 [2] f2 d8 [2] fe d2 [2] e9 d9 [2] f2 97 [2] cf }

  condition:
    any of them
}