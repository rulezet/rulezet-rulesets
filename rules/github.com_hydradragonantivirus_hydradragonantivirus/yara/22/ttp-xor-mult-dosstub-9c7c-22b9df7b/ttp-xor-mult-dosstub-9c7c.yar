rule TTP_XOR_MULT_DOSStub_9c7c {
  strings:
    $key_9c7c = { c8 14 [2] bc 0c [2] fb 0e [2] bc 1f [2] f2 13 [2] fe 19 [2] e9 12 [2] f2 5c [2] cf }

  condition:
    any of them
}