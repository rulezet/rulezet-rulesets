rule TTP_XOR_MULT_DOSStub_9c32 {
  strings:
    $key_9c32 = { c8 5a [2] bc 42 [2] fb 40 [2] bc 51 [2] f2 5d [2] fe 57 [2] e9 5c [2] f2 12 [2] cf }

  condition:
    any of them
}