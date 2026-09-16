rule TTP_XOR_MULT_DOSStub_9c9b {
  strings:
    $key_9c9b = { c8 f3 [2] bc eb [2] fb e9 [2] bc f8 [2] f2 f4 [2] fe fe [2] e9 f5 [2] f2 bb [2] cf }

  condition:
    any of them
}