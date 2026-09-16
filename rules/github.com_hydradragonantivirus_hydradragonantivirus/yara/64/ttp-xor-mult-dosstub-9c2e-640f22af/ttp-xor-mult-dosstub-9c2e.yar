rule TTP_XOR_MULT_DOSStub_9c2e {
  strings:
    $key_9c2e = { c8 46 [2] bc 5e [2] fb 5c [2] bc 4d [2] f2 41 [2] fe 4b [2] e9 40 [2] f2 0e [2] cf }

  condition:
    any of them
}