rule TTP_XOR_MULT_DOSStub_9cf4 {
  strings:
    $key_9cf4 = { c8 9c [2] bc 84 [2] fb 86 [2] bc 97 [2] f2 9b [2] fe 91 [2] e9 9a [2] f2 d4 [2] cf }

  condition:
    any of them
}