rule TTP_XOR_MULT_DOSStub_9c5d {
  strings:
    $key_9c5d = { c8 35 [2] bc 2d [2] fb 2f [2] bc 3e [2] f2 32 [2] fe 38 [2] e9 33 [2] f2 7d [2] cf }

  condition:
    any of them
}