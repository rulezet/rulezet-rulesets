rule TTP_XOR_MULT_DOSStub_9c0e {
  strings:
    $key_9c0e = { c8 66 [2] bc 7e [2] fb 7c [2] bc 6d [2] f2 61 [2] fe 6b [2] e9 60 [2] f2 2e [2] cf }

  condition:
    any of them
}