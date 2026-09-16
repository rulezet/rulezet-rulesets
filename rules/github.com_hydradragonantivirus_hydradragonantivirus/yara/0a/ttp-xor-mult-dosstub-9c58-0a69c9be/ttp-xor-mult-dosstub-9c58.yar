rule TTP_XOR_MULT_DOSStub_9c58 {
  strings:
    $key_9c58 = { c8 30 [2] bc 28 [2] fb 2a [2] bc 3b [2] f2 37 [2] fe 3d [2] e9 36 [2] f2 78 [2] cf }

  condition:
    any of them
}