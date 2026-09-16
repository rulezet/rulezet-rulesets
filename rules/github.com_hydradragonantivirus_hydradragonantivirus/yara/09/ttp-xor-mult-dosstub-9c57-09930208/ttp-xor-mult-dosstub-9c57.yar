rule TTP_XOR_MULT_DOSStub_9c57 {
  strings:
    $key_9c57 = { c8 3f [2] bc 27 [2] fb 25 [2] bc 34 [2] f2 38 [2] fe 32 [2] e9 39 [2] f2 77 [2] cf }

  condition:
    any of them
}