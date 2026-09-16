rule TTP_XOR_MULT_DOSStub_9c00 {
  strings:
    $key_9c00 = { c8 68 [2] bc 70 [2] fb 72 [2] bc 63 [2] f2 6f [2] fe 65 [2] e9 6e [2] f2 20 [2] cf }

  condition:
    any of them
}