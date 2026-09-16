rule TTP_XOR_MULT_DOSStub_9ce4 {
  strings:
    $key_9ce4 = { c8 8c [2] bc 94 [2] fb 96 [2] bc 87 [2] f2 8b [2] fe 81 [2] e9 8a [2] f2 c4 [2] cf }

  condition:
    any of them
}