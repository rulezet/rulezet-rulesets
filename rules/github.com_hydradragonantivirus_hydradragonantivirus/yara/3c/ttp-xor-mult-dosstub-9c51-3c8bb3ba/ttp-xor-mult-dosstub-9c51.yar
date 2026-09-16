rule TTP_XOR_MULT_DOSStub_9c51 {
  strings:
    $key_9c51 = { c8 39 [2] bc 21 [2] fb 23 [2] bc 32 [2] f2 3e [2] fe 34 [2] e9 3f [2] f2 71 [2] cf }

  condition:
    any of them
}