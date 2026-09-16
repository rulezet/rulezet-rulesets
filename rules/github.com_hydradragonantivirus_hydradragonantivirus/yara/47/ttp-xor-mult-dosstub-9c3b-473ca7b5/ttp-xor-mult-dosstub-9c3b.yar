rule TTP_XOR_MULT_DOSStub_9c3b {
  strings:
    $key_9c3b = { c8 53 [2] bc 4b [2] fb 49 [2] bc 58 [2] f2 54 [2] fe 5e [2] e9 55 [2] f2 1b [2] cf }

  condition:
    any of them
}