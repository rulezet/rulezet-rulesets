rule TTP_XOR_MULT_DOSStub_9c1e {
  strings:
    $key_9c1e = { c8 76 [2] bc 6e [2] fb 6c [2] bc 7d [2] f2 71 [2] fe 7b [2] e9 70 [2] f2 3e [2] cf }

  condition:
    any of them
}