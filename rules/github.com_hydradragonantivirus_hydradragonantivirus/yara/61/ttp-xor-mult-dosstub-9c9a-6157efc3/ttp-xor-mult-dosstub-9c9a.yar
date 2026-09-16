rule TTP_XOR_MULT_DOSStub_9c9a {
  strings:
    $key_9c9a = { c8 f2 [2] bc ea [2] fb e8 [2] bc f9 [2] f2 f5 [2] fe ff [2] e9 f4 [2] f2 ba [2] cf }

  condition:
    any of them
}