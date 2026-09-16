rule TTP_XOR_MULT_DOSStub_9c1a {
  strings:
    $key_9c1a = { c8 72 [2] bc 6a [2] fb 68 [2] bc 79 [2] f2 75 [2] fe 7f [2] e9 74 [2] f2 3a [2] cf }

  condition:
    any of them
}