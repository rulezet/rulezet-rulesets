rule TTP_XOR_MULT_DOSStub_9c6f {
  strings:
    $key_9c6f = { c8 07 [2] bc 1f [2] fb 1d [2] bc 0c [2] f2 00 [2] fe 0a [2] e9 01 [2] f2 4f [2] cf }

  condition:
    any of them
}