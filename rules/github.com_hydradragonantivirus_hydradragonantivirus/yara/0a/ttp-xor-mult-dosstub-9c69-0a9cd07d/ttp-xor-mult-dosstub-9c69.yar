rule TTP_XOR_MULT_DOSStub_9c69 {
  strings:
    $key_9c69 = { c8 01 [2] bc 19 [2] fb 1b [2] bc 0a [2] f2 06 [2] fe 0c [2] e9 07 [2] f2 49 [2] cf }

  condition:
    any of them
}