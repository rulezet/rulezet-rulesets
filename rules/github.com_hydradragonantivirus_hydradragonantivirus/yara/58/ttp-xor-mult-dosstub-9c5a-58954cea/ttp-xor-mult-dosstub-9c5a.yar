rule TTP_XOR_MULT_DOSStub_9c5a {
  strings:
    $key_9c5a = { c8 32 [2] bc 2a [2] fb 28 [2] bc 39 [2] f2 35 [2] fe 3f [2] e9 34 [2] f2 7a [2] cf }

  condition:
    any of them
}