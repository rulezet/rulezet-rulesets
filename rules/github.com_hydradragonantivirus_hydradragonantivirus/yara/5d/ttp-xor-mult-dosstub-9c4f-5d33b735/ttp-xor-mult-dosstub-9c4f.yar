rule TTP_XOR_MULT_DOSStub_9c4f {
  strings:
    $key_9c4f = { c8 27 [2] bc 3f [2] fb 3d [2] bc 2c [2] f2 20 [2] fe 2a [2] e9 21 [2] f2 6f [2] cf }

  condition:
    any of them
}