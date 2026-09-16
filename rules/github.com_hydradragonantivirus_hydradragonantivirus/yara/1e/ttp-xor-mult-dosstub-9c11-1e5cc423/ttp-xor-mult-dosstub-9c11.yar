rule TTP_XOR_MULT_DOSStub_9c11 {
  strings:
    $key_9c11 = { c8 79 [2] bc 61 [2] fb 63 [2] bc 72 [2] f2 7e [2] fe 74 [2] e9 7f [2] f2 31 [2] cf }

  condition:
    any of them
}