rule TTP_XOR_MULT_DOSStub_9c4b {
  strings:
    $key_9c4b = { c8 23 [2] bc 3b [2] fb 39 [2] bc 28 [2] f2 24 [2] fe 2e [2] e9 25 [2] f2 6b [2] cf }

  condition:
    any of them
}