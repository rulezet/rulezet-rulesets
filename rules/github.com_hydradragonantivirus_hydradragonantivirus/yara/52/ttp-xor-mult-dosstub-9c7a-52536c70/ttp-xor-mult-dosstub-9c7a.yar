rule TTP_XOR_MULT_DOSStub_9c7a {
  strings:
    $key_9c7a = { c8 12 [2] bc 0a [2] fb 08 [2] bc 19 [2] f2 15 [2] fe 1f [2] e9 14 [2] f2 5a [2] cf }

  condition:
    any of them
}