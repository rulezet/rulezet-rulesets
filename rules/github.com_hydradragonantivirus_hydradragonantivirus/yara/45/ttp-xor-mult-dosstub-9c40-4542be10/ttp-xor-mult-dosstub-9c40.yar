rule TTP_XOR_MULT_DOSStub_9c40 {
  strings:
    $key_9c40 = { c8 28 [2] bc 30 [2] fb 32 [2] bc 23 [2] f2 2f [2] fe 25 [2] e9 2e [2] f2 60 [2] cf }

  condition:
    any of them
}