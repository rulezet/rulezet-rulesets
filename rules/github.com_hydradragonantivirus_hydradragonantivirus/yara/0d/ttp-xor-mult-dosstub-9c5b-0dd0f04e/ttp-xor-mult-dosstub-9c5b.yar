rule TTP_XOR_MULT_DOSStub_9c5b {
  strings:
    $key_9c5b = { c8 33 [2] bc 2b [2] fb 29 [2] bc 38 [2] f2 34 [2] fe 3e [2] e9 35 [2] f2 7b [2] cf }

  condition:
    any of them
}