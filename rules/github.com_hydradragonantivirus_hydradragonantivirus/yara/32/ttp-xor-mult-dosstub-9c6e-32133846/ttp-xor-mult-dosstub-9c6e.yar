rule TTP_XOR_MULT_DOSStub_9c6e {
  strings:
    $key_9c6e = { c8 06 [2] bc 1e [2] fb 1c [2] bc 0d [2] f2 01 [2] fe 0b [2] e9 00 [2] f2 4e [2] cf }

  condition:
    any of them
}