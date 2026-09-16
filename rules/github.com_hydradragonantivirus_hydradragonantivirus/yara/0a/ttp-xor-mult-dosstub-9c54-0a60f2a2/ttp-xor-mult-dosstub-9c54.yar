rule TTP_XOR_MULT_DOSStub_9c54 {
  strings:
    $key_9c54 = { c8 3c [2] bc 24 [2] fb 26 [2] bc 37 [2] f2 3b [2] fe 31 [2] e9 3a [2] f2 74 [2] cf }

  condition:
    any of them
}