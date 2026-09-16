rule TTP_XOR_MULT_DOSStub_9c04 {
  strings:
    $key_9c04 = { c8 6c [2] bc 74 [2] fb 76 [2] bc 67 [2] f2 6b [2] fe 61 [2] e9 6a [2] f2 24 [2] cf }

  condition:
    any of them
}