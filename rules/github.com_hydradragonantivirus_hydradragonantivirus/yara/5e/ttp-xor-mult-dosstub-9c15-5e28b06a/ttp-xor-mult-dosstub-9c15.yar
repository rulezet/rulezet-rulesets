rule TTP_XOR_MULT_DOSStub_9c15 {
  strings:
    $key_9c15 = { c8 7d [2] bc 65 [2] fb 67 [2] bc 76 [2] f2 7a [2] fe 70 [2] e9 7b [2] f2 35 [2] cf }

  condition:
    any of them
}