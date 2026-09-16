rule TTP_XOR_MULT_DOSStub_9c5c {
  strings:
    $key_9c5c = { c8 34 [2] bc 2c [2] fb 2e [2] bc 3f [2] f2 33 [2] fe 39 [2] e9 32 [2] f2 7c [2] cf }

  condition:
    any of them
}