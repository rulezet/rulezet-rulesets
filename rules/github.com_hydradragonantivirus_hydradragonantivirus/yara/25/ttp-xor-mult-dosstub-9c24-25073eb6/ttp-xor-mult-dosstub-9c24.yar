rule TTP_XOR_MULT_DOSStub_9c24 {
  strings:
    $key_9c24 = { c8 4c [2] bc 54 [2] fb 56 [2] bc 47 [2] f2 4b [2] fe 41 [2] e9 4a [2] f2 04 [2] cf }

  condition:
    any of them
}