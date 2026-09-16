rule TTP_XOR_MULT_DOSStub_9c26 {
  strings:
    $key_9c26 = { c8 4e [2] bc 56 [2] fb 54 [2] bc 45 [2] f2 49 [2] fe 43 [2] e9 48 [2] f2 06 [2] cf }

  condition:
    any of them
}