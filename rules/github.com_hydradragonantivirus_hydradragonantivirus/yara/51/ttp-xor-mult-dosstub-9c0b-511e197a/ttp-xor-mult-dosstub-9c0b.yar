rule TTP_XOR_MULT_DOSStub_9c0b {
  strings:
    $key_9c0b = { c8 63 [2] bc 7b [2] fb 79 [2] bc 68 [2] f2 64 [2] fe 6e [2] e9 65 [2] f2 2b [2] cf }

  condition:
    any of them
}