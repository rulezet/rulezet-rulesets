rule TTP_XOR_MULT_DOSStub_9c4d {
  strings:
    $key_9c4d = { c8 25 [2] bc 3d [2] fb 3f [2] bc 2e [2] f2 22 [2] fe 28 [2] e9 23 [2] f2 6d [2] cf }

  condition:
    any of them
}