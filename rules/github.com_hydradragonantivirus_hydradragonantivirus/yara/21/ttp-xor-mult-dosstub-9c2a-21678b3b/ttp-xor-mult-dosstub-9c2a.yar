rule TTP_XOR_MULT_DOSStub_9c2a {
  strings:
    $key_9c2a = { c8 42 [2] bc 5a [2] fb 58 [2] bc 49 [2] f2 45 [2] fe 4f [2] e9 44 [2] f2 0a [2] cf }

  condition:
    any of them
}