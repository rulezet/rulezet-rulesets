rule TTP_XOR_MULT_DOSStub_9c19 {
  strings:
    $key_9c19 = { c8 71 [2] bc 69 [2] fb 6b [2] bc 7a [2] f2 76 [2] fe 7c [2] e9 77 [2] f2 39 [2] cf }

  condition:
    any of them
}