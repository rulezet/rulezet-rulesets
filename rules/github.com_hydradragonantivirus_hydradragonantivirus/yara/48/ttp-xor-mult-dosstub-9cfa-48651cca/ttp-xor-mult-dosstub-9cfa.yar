rule TTP_XOR_MULT_DOSStub_9cfa {
  strings:
    $key_9cfa = { c8 92 [2] bc 8a [2] fb 88 [2] bc 99 [2] f2 95 [2] fe 9f [2] e9 94 [2] f2 da [2] cf }

  condition:
    any of them
}