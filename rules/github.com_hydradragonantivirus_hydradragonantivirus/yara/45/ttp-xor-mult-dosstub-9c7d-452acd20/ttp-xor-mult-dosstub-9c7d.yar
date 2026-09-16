rule TTP_XOR_MULT_DOSStub_9c7d {
  strings:
    $key_9c7d = { c8 15 [2] bc 0d [2] fb 0f [2] bc 1e [2] f2 12 [2] fe 18 [2] e9 13 [2] f2 5d [2] cf }

  condition:
    any of them
}