rule TTP_XOR_MULT_DOSStub_9c3e {
  strings:
    $key_9c3e = { c8 56 [2] bc 4e [2] fb 4c [2] bc 5d [2] f2 51 [2] fe 5b [2] e9 50 [2] f2 1e [2] cf }

  condition:
    any of them
}