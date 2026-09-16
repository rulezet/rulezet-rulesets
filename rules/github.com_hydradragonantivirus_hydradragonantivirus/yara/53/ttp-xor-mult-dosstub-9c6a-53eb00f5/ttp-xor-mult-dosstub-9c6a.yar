rule TTP_XOR_MULT_DOSStub_9c6a {
  strings:
    $key_9c6a = { c8 02 [2] bc 1a [2] fb 18 [2] bc 09 [2] f2 05 [2] fe 0f [2] e9 04 [2] f2 4a [2] cf }

  condition:
    any of them
}