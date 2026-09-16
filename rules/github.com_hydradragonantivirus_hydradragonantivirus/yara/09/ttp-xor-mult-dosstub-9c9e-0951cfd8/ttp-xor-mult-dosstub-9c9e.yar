rule TTP_XOR_MULT_DOSStub_9c9e {
  strings:
    $key_9c9e = { c8 f6 [2] bc ee [2] fb ec [2] bc fd [2] f2 f1 [2] fe fb [2] e9 f0 [2] f2 be [2] cf }

  condition:
    any of them
}