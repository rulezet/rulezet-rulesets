rule TTP_XOR_MULT_DOSStub_9c2c {
  strings:
    $key_9c2c = { c8 44 [2] bc 5c [2] fb 5e [2] bc 4f [2] f2 43 [2] fe 49 [2] e9 42 [2] f2 0c [2] cf }

  condition:
    any of them
}