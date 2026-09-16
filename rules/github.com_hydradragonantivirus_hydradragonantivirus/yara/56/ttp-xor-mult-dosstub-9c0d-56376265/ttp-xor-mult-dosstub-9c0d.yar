rule TTP_XOR_MULT_DOSStub_9c0d {
  strings:
    $key_9c0d = { c8 65 [2] bc 7d [2] fb 7f [2] bc 6e [2] f2 62 [2] fe 68 [2] e9 63 [2] f2 2d [2] cf }

  condition:
    any of them
}