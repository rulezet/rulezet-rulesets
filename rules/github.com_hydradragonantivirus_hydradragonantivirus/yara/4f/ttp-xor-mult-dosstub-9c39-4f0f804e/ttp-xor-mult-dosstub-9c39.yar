rule TTP_XOR_MULT_DOSStub_9c39 {
  strings:
    $key_9c39 = { c8 51 [2] bc 49 [2] fb 4b [2] bc 5a [2] f2 56 [2] fe 5c [2] e9 57 [2] f2 19 [2] cf }

  condition:
    any of them
}