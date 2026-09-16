rule TTP_XOR_MULT_DOSStub_9c38 {
  strings:
    $key_9c38 = { c8 50 [2] bc 48 [2] fb 4a [2] bc 5b [2] f2 57 [2] fe 5d [2] e9 56 [2] f2 18 [2] cf }

  condition:
    any of them
}