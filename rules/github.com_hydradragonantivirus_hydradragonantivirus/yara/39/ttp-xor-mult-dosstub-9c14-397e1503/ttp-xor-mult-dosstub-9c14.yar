rule TTP_XOR_MULT_DOSStub_9c14 {
  strings:
    $key_9c14 = { c8 7c [2] bc 64 [2] fb 66 [2] bc 77 [2] f2 7b [2] fe 71 [2] e9 7a [2] f2 34 [2] cf }

  condition:
    any of them
}