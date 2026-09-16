rule TTP_XOR_MULT_DOSStub_9c5f {
  strings:
    $key_9c5f = { c8 37 [2] bc 2f [2] fb 2d [2] bc 3c [2] f2 30 [2] fe 3a [2] e9 31 [2] f2 7f [2] cf }

  condition:
    any of them
}