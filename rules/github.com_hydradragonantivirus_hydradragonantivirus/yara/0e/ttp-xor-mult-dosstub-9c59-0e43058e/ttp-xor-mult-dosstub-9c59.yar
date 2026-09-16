rule TTP_XOR_MULT_DOSStub_9c59 {
  strings:
    $key_9c59 = { c8 31 [2] bc 29 [2] fb 2b [2] bc 3a [2] f2 36 [2] fe 3c [2] e9 37 [2] f2 79 [2] cf }

  condition:
    any of them
}