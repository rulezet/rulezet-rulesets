rule TTP_XOR_MULT_DOSStub_9cf0 {
  strings:
    $key_9cf0 = { c8 98 [2] bc 80 [2] fb 82 [2] bc 93 [2] f2 9f [2] fe 95 [2] e9 9e [2] f2 d0 [2] cf }

  condition:
    any of them
}