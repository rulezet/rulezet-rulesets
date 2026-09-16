rule TTP_XOR_MULT_DOSStub_9c1c {
  strings:
    $key_9c1c = { c8 74 [2] bc 6c [2] fb 6e [2] bc 7f [2] f2 73 [2] fe 79 [2] e9 72 [2] f2 3c [2] cf }

  condition:
    any of them
}