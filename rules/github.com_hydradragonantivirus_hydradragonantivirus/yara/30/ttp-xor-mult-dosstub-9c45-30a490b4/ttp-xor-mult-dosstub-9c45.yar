rule TTP_XOR_MULT_DOSStub_9c45 {
  strings:
    $key_9c45 = { c8 2d [2] bc 35 [2] fb 37 [2] bc 26 [2] f2 2a [2] fe 20 [2] e9 2b [2] f2 65 [2] cf }

  condition:
    any of them
}