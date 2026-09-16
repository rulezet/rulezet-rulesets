rule TTP_XOR_MULT_DOSStub_9c0c {
  strings:
    $key_9c0c = { c8 64 [2] bc 7c [2] fb 7e [2] bc 6f [2] f2 63 [2] fe 69 [2] e9 62 [2] f2 2c [2] cf }

  condition:
    any of them
}