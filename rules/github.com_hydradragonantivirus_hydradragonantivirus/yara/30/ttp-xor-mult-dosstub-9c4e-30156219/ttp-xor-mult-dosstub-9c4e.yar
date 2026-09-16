rule TTP_XOR_MULT_DOSStub_9c4e {
  strings:
    $key_9c4e = { c8 26 [2] bc 3e [2] fb 3c [2] bc 2d [2] f2 21 [2] fe 2b [2] e9 20 [2] f2 6e [2] cf }

  condition:
    any of them
}