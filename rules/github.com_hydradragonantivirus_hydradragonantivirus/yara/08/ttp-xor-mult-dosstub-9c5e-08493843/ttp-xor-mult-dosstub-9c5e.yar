rule TTP_XOR_MULT_DOSStub_9c5e {
  strings:
    $key_9c5e = { c8 36 [2] bc 2e [2] fb 2c [2] bc 3d [2] f2 31 [2] fe 3b [2] e9 30 [2] f2 7e [2] cf }

  condition:
    any of them
}