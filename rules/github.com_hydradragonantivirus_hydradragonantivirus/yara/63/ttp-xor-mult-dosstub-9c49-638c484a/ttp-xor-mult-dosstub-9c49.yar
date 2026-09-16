rule TTP_XOR_MULT_DOSStub_9c49 {
  strings:
    $key_9c49 = { c8 21 [2] bc 39 [2] fb 3b [2] bc 2a [2] f2 26 [2] fe 2c [2] e9 27 [2] f2 69 [2] cf }

  condition:
    any of them
}