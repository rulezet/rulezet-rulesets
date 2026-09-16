rule TTP_XOR_MULT_DOSStub_9c0f {
  strings:
    $key_9c0f = { c8 67 [2] bc 7f [2] fb 7d [2] bc 6c [2] f2 60 [2] fe 6a [2] e9 61 [2] f2 2f [2] cf }

  condition:
    any of them
}