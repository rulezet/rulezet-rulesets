rule TTP_XOR_MULT_DOSStub_9c06 {
  strings:
    $key_9c06 = { c8 6e [2] bc 76 [2] fb 74 [2] bc 65 [2] f2 69 [2] fe 63 [2] e9 68 [2] f2 26 [2] cf }

  condition:
    any of them
}