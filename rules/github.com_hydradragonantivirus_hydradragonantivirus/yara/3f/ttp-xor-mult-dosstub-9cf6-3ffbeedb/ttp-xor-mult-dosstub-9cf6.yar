rule TTP_XOR_MULT_DOSStub_9cf6 {
  strings:
    $key_9cf6 = { c8 9e [2] bc 86 [2] fb 84 [2] bc 95 [2] f2 99 [2] fe 93 [2] e9 98 [2] f2 d6 [2] cf }

  condition:
    any of them
}