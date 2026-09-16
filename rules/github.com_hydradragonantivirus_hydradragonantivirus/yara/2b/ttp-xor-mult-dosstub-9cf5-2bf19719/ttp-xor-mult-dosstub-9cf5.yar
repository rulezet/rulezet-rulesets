rule TTP_XOR_MULT_DOSStub_9cf5 {
  strings:
    $key_9cf5 = { c8 9d [2] bc 85 [2] fb 87 [2] bc 96 [2] f2 9a [2] fe 90 [2] e9 9b [2] f2 d5 [2] cf }

  condition:
    any of them
}