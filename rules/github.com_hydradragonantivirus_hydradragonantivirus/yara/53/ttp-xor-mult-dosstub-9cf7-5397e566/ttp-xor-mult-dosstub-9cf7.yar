rule TTP_XOR_MULT_DOSStub_9cf7 {
  strings:
    $key_9cf7 = { c8 9f [2] bc 87 [2] fb 85 [2] bc 94 [2] f2 98 [2] fe 92 [2] e9 99 [2] f2 d7 [2] cf }

  condition:
    any of them
}