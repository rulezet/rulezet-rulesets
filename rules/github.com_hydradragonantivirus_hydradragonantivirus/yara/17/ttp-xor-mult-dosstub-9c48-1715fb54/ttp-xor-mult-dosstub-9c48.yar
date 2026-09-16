rule TTP_XOR_MULT_DOSStub_9c48 {
  strings:
    $key_9c48 = { c8 20 [2] bc 38 [2] fb 3a [2] bc 2b [2] f2 27 [2] fe 2d [2] e9 26 [2] f2 68 [2] cf }

  condition:
    any of them
}